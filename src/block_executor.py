"""
Phase 4D — Block executor for the live agent.

Takes a Decision (from decision_engine.py) and applies the appropriate action:
  - ALLOW  -> log to decisions.jsonl, do nothing
  - WATCH  -> log to decisions.jsonl + watch.jsonl, do nothing
  - BLOCK  -> safety-check, then SSH to the server and `ipset add ml_blocks <ip>`

This is the single most safety-critical module in the system. Every safety
layer below exists because the failure mode of "agent blocks a legitimate IP
permanently" is much worse than "agent fails to block an attacker for an
extra minute". When in doubt, the executor refuses.

Six safety layers (this module owns 1, 5, 6 and depends on 2-4 upstream):
  1. Paranoid allowlist recheck (re-verified here even though 4B checked)
  2. RF confidence threshold       (in decision engine)
  3. Conservative combining policy (in decision engine)
  4. ipset timeout = 3600s         (set when the ipset was created)
  5. Rate limit (default 5/min real blocks)
  6. DRY-RUN mode (default True; must be explicitly disabled)

Audit trail: every handle() call appends one line to data/agent/decisions.jsonl,
regardless of verdict or outcome. WATCH verdicts also get a line in watch.jsonl
for easier review.

Phase 5A.0 update: handle() now accepts an optional `flow` dict. When provided,
the FULL feature vector is written to decisions.jsonl under a "flow" key —
this is what Phase 5 retraining will consume. Test code and old callers can
omit it; the JSONL just won't have the "flow" key for those records.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional
import json
import shlex
import time


class ExecutorOutcome(str, Enum):
    """What actually happened when handle() processed a Decision."""
    ALLOW_NOOP          = "ALLOW_NOOP"
    WATCH_LOGGED        = "WATCH_LOGGED"
    REFUSED_ALLOWLIST   = "REFUSED_ALLOWLIST"
    SKIPPED_DUPLICATE   = "SKIPPED_DUPLICATE"
    REFUSED_RATE_LIMIT  = "REFUSED_RATE_LIMIT"
    DRY_RUN_BLOCK       = "DRY_RUN_BLOCK"
    REAL_BLOCK          = "REAL_BLOCK"
    FAILED_BLOCK        = "FAILED_BLOCK"


@dataclass
class ExecutorResult:
    """Returned from every handle() call. Never raised on policy refusals."""
    outcome: ExecutorOutcome
    src_ip: str
    detail: Optional[str] = None   # e.g. ipset stderr on FAILED_BLOCK

    def to_dict(self) -> dict:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


class BlockExecutor:
    """
    Safety-wrapped firewall mutation layer.

    Parameters
    ----------
    ssh_conn_factory : callable
        A zero-arg callable that returns an SSH context manager.
        Pass `src.ssh_client.ssh_connection` directly.
    allowlist : iterable of str
        IPs that must never be blocked under any circumstance. Should be
        the SAME list passed to DecisionEngine; the executor re-checks
        defensively. Caller is responsible for keeping these in sync.
    rate_limit_per_min : int
        Maximum number of REAL blocks per rolling 60-second window. Refused
        attempts and dry-run blocks do NOT count against the limit.
    dry_run : bool
        If True (default), BLOCK verdicts are logged as DRY_RUN_BLOCK and the
        ipset is NOT touched. Flip to False explicitly to arm the agent.
    log_dir : Path
        Directory where decisions.jsonl and watch.jsonl will be appended to.
        Created if missing.
    ipset_name : str
        Name of the ipset on the server. Default "ml_blocks" matches 4A setup.
    """

    def __init__(
        self,
        ssh_conn_factory: Callable,
        allowlist: Iterable[str],
        *,
        rate_limit_per_min: int = 5,
        dry_run: bool = True,
        log_dir: Path = Path("data/agent"),
        ipset_name: str = "ml_blocks",
    ):
        self.ssh_conn_factory = ssh_conn_factory
        self.allowlist = set(allowlist)
        self.rate_limit_per_min = rate_limit_per_min
        self.dry_run = dry_run
        self.ipset_name = ipset_name

        # Log files. Open in append mode so prior runs are preserved.
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._decisions_path = self.log_dir / "decisions.jsonl"
        self._watch_path     = self.log_dir / "watch.jsonl"
        self._decisions_fh = self._decisions_path.open("a", encoding="utf-8")
        self._watch_fh     = self._watch_path.open("a", encoding="utf-8")

        # In-memory tracking of IPs we've already blocked this run. Fast-path
        # to avoid an SSH round trip on every duplicate. May diverge from the
        # server's ipset due to timeout expiry — call resync_from_server() if
        # that matters.
        self._blocked_ips: set[str] = set()

        # Rolling window of real-block timestamps for the rate limiter.
        self._recent_block_times: deque[float] = deque()

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def handle(self, decision, flow: Optional[dict] = None) -> ExecutorResult:
        """
        Process one Decision and return an ExecutorResult.

        Never raises on policy refusal. Only raises on programmer errors
        (e.g. malformed Decision). SSH/ipset failures are reported as
        FAILED_BLOCK results, not exceptions.

        Parameters
        ----------
        decision : Decision
            The verdict from DecisionEngine.decide().
        flow : dict, optional
            The full feature dict that was passed to the decision engine.
            When provided, it is recorded verbatim in decisions.jsonl under
            the "flow" key. Phase 5 retraining requires this. Test code can
            omit it; the JSONL record will simply lack the "flow" key.
        """
        verdict = decision.verdict.value if hasattr(decision.verdict, "value") \
                  else str(decision.verdict)

        # ALLOW: log and return.
        if verdict == "ALLOW":
            result = ExecutorResult(ExecutorOutcome.ALLOW_NOOP, decision.src_ip)
            self._log_decision(decision, result, flow)
            return result

        # WATCH: log to both files and return.
        if verdict == "WATCH":
            result = ExecutorResult(ExecutorOutcome.WATCH_LOGGED, decision.src_ip)
            self._log_decision(decision, result, flow)
            self._log_watch(decision, flow)
            return result

        # BLOCK: run the gauntlet of safety checks.
        if verdict != "BLOCK":
            # Defensive: unknown verdict shouldn't reach us, but if it does,
            # treat as a no-op rather than a crash.
            result = ExecutorResult(
                ExecutorOutcome.ALLOW_NOOP, decision.src_ip,
                detail=f"unknown verdict {verdict!r}, treated as no-op",
            )
            self._log_decision(decision, result, flow)
            return result

        # 1. Paranoid allowlist recheck — do NOT trust upstream.
        if decision.src_ip in self.allowlist:
            result = ExecutorResult(
                ExecutorOutcome.REFUSED_ALLOWLIST, decision.src_ip,
                detail=f"{decision.src_ip} is on the allowlist; refusing block",
            )
            self._log_decision(decision, result, flow)
            return result

        # 2. Already-blocked dedup.
        if decision.src_ip in self._blocked_ips:
            result = ExecutorResult(
                ExecutorOutcome.SKIPPED_DUPLICATE, decision.src_ip,
                detail="already blocked this run",
            )
            self._log_decision(decision, result, flow)
            return result

        # 3. Rate limit.
        if not self._rate_limit_check():
            result = ExecutorResult(
                ExecutorOutcome.REFUSED_RATE_LIMIT, decision.src_ip,
                detail=f"more than {self.rate_limit_per_min} real blocks in the last 60s",
            )
            self._log_decision(decision, result, flow)
            return result

        # 4. DRY-RUN gate.
        if self.dry_run:
            result = ExecutorResult(
                ExecutorOutcome.DRY_RUN_BLOCK, decision.src_ip,
                detail="dry_run=True; ipset NOT modified",
            )
            self._log_decision(decision, result, flow)
            return result

        # 5. Real path — SSH and apply the block.
        result = self._apply_block(decision.src_ip)
        if result.outcome == ExecutorOutcome.REAL_BLOCK:
            self._blocked_ips.add(decision.src_ip)
            self._recent_block_times.append(time.monotonic())
        self._log_decision(decision, result, flow)
        return result

    def resync_from_server(self) -> int:
        """
        Reconcile the in-memory blocked set with the server's current ipset.
        Returns the number of IPs found on the server.

        Useful at agent startup so we don't try to re-block IPs whose timeout
        is still ticking from a previous run.
        """
        cmd = f"sudo ipset list {shlex.quote(self.ipset_name)}"
        with self.ssh_conn_factory() as client:
            stdin, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc  = stdout.channel.recv_exit_status()
        if rc != 0:
            raise RuntimeError(
                f"resync_from_server: ipset list failed (rc={rc}): {err.strip()}"
            )

        # ipset list output has a "Members:" section; one IP per line after it.
        ips = set()
        in_members = False
        for line in out.splitlines():
            if line.startswith("Members:"):
                in_members = True
                continue
            if in_members:
                # Lines look like:  "192.168.56.103 timeout 3580"
                token = line.strip().split()
                if token:
                    ips.add(token[0])

        self._blocked_ips = ips
        return len(ips)

    def shutdown(self):
        """Flush and close log files. Idempotent."""
        for fh_name in ("_decisions_fh", "_watch_fh"):
            fh = getattr(self, fh_name, None)
            if fh and not fh.closed:
                try:
                    fh.flush()
                    fh.close()
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()
        return False

    # -------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------

    def _rate_limit_check(self) -> bool:
        """
        Drop timestamps older than 60s, then check if we're under the limit.
        Returns True if a new block is allowed, False if we should refuse.
        """
        now = time.monotonic()
        cutoff = now - 60.0
        while self._recent_block_times and self._recent_block_times[0] < cutoff:
            self._recent_block_times.popleft()
        return len(self._recent_block_times) < self.rate_limit_per_min

    def _apply_block(self, ip: str) -> ExecutorResult:
        """
        SSH to the server and run `sudo ipset add ml_blocks <ip>`.

        Uses `ipset add -exist` so that re-adding an IP that's still timing
        out is a no-op rather than an error. This keeps the operation
        idempotent on the server side even if our in-memory dedup misses.
        """
        cmd = f"sudo ipset add -exist {shlex.quote(self.ipset_name)} {shlex.quote(ip)}"
        try:
            with self.ssh_conn_factory() as client:
                stdin, stdout, stderr = client.exec_command(cmd)
                err = stderr.read().decode("utf-8", errors="replace")
                rc  = stdout.channel.recv_exit_status()
        except Exception as e:
            return ExecutorResult(
                ExecutorOutcome.FAILED_BLOCK, ip,
                detail=f"SSH/exec error: {e!r}",
            )

        if rc == 0:
            return ExecutorResult(ExecutorOutcome.REAL_BLOCK, ip)

        return ExecutorResult(
            ExecutorOutcome.FAILED_BLOCK, ip,
            detail=f"ipset add failed (rc={rc}): {err.strip()}",
        )

    def _log_decision(self, decision, result: ExecutorResult,
                      flow: Optional[dict] = None):
        """
        Append one JSON line per handle() call to decisions.jsonl.

        If `flow` is provided, the full feature dict is recorded under the
        "flow" key. Phase 5 retraining will use this to reconstruct training
        rows. Older entries without "flow" are still valid audit records;
        they just can't be replayed for retraining.
        """
        record = {
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "decision":  decision.to_dict(),
            "executor": {
                "outcome": result.outcome.value,
                "detail":  result.detail,
                "dry_run": self.dry_run,
            },
        }
        if flow is not None:
            # Strip non-feature keys that are already in decision.to_dict().
            # Coerce numpy / pandas scalars to JSON-safe Python types.
            safe_flow = {}
            for k, v in flow.items():
                if k in ("src_ip", "window_start"):
                    continue
                safe_flow[k] = _json_safe(v)
            record["flow"] = safe_flow

        self._decisions_fh.write(json.dumps(record) + "\n")
        self._decisions_fh.flush()

    def _log_watch(self, decision, flow: Optional[dict] = None):
        """Append a separate line for WATCH verdicts for easy review."""
        record = {
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "decision":  decision.to_dict(),
        }
        if flow is not None:
            safe_flow = {}
            for k, v in flow.items():
                if k in ("src_ip", "window_start"):
                    continue
                safe_flow[k] = _json_safe(v)
            record["flow"] = safe_flow

        self._watch_fh.write(json.dumps(record) + "\n")
        self._watch_fh.flush()


def _json_safe(v):
    """
    Best-effort coercion of a value to something json.dumps will accept.
    Numpy scalars, datetimes, pandas Timestamps, and similar exotic types
    are converted to Python primitives. Unknown types fall back to str(v).
    """
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    # Numpy / pandas scalars
    if hasattr(v, "item"):
        try:
            return v.item()
        except Exception:
            pass
    # Datetime-like
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:
            pass
    return str(v)