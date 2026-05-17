"""
Phase 4D — Smoke tests for the BlockExecutor.

Run from project root:   python -m scripts.test_block_executor

Tests are grouped:
  1. FAKE-SSH tests (no VM needed)  — validate policy logic
  2. REAL-SSH test (requires the VM) — end-to-end check that ipset add works
     using a TEST-NET-1 IP (192.0.2.1) which is reserved-for-docs and never
     a real client. Run `--no-live` to skip this.

Style: each test prints "PASS" or "FAIL ..." and the script exits 0 only if
everything passes. Designed for eyeballing in PyCharm's console.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

# Make `src` importable when run as a script from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.block_executor import BlockExecutor, ExecutorOutcome
from src.decision_engine import Decision, Verdict



# ----- Helpers --------------------------------------------------------------

def make_decision(src_ip: str, verdict: Verdict, rf_prob: float = 0.95,
                  if_anomalous: bool = True) -> Decision:
    """Build a Decision with sensible defaults for testing."""
    return Decision(
        src_ip=src_ip,
        window_start="2026-05-16T19:00:00+03:00",
        verdict=verdict,
        rf_prediction=1 if verdict == Verdict.BLOCK else 0,
        rf_probability=rf_prob,
        if_anomalous=if_anomalous,
        if_score=0.18,
        on_allowlist=(verdict == Verdict.ALLOW),
        reason=f"test-decision {verdict.value}",
        top_features={"syn_only_ratio": 0.98, "unique_dst_ports": 100.0},
    )


class FakeSSHChannel:
    def __init__(self, rc=0):
        self._rc = rc
    def recv_exit_status(self):
        return self._rc


class FakeSSHFile:
    def __init__(self, data: bytes, channel: FakeSSHChannel = None):
        self._data = data
        self.channel = channel
    def read(self):
        return self._data


class FakeSSHClient:
    """
    Records every command exec_command() receives. Pretends success unless
    `fail_with` is set, in which case it returns nonzero rc and stderr.
    """
    def __init__(self, fail_with: tuple[int, str] = None,
                 stdout_data: bytes = b""):
        self.commands: list[str] = []
        self._fail = fail_with
        self._stdout_data = stdout_data

    def exec_command(self, cmd):
        self.commands.append(cmd)
        if self._fail:
            rc, err = self._fail
            channel = FakeSSHChannel(rc)
            return (
                None,
                FakeSSHFile(self._stdout_data, channel),
                FakeSSHFile(err.encode("utf-8"), channel),
            )
        channel = FakeSSHChannel(0)
        return (
            None,
            FakeSSHFile(self._stdout_data, channel),
            FakeSSHFile(b"", channel),
        )

    def close(self):
        pass


def make_fake_factory(fail_with=None, stdout_data: bytes = b""):
    """
    Returns (factory, client) — the factory is what we pass to BlockExecutor,
    and the client lets tests inspect what commands were issued.
    """
    client = FakeSSHClient(fail_with=fail_with, stdout_data=stdout_data)
    @contextmanager
    def factory():
        yield client
    return factory, client


# ----- Assertions ------------------------------------------------------------

def _check(label: str, cond: bool, *, detail: str = ""):
    if cond:
        print(f"  PASS  {label}")
        return True
    print(f"  FAIL  {label}  {detail}")
    return False


# ----- Tests -----------------------------------------------------------------

ALLOWLIST = ["192.168.56.1", "127.0.0.1", "10.0.2.2", "10.0.2.3"]


def test_allow_verdict_is_noop(tmpdir: Path) -> bool:
    print("\n[test] ALLOW verdict -> ALLOW_NOOP, no SSH")
    factory, client = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=True, log_dir=tmpdir) as ex:
        d = make_decision("203.0.113.10", Verdict.ALLOW)
        r = ex.handle(d)
    ok = True
    ok &= _check("outcome is ALLOW_NOOP", r.outcome == ExecutorOutcome.ALLOW_NOOP)
    ok &= _check("no SSH commands issued", client.commands == [],
                 detail=f"got {client.commands}")
    return ok


def test_watch_verdict_logs_both_files(tmpdir: Path) -> bool:
    print("\n[test] WATCH verdict -> writes to decisions.jsonl AND watch.jsonl")
    factory, client = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=True, log_dir=tmpdir) as ex:
        d = make_decision("203.0.113.20", Verdict.WATCH)
        r = ex.handle(d)
    decisions = (tmpdir / "decisions.jsonl").read_text(encoding="utf-8").strip().splitlines()
    watch     = (tmpdir / "watch.jsonl").read_text(encoding="utf-8").strip().splitlines()
    ok = True
    ok &= _check("outcome is WATCH_LOGGED", r.outcome == ExecutorOutcome.WATCH_LOGGED)
    ok &= _check("decisions.jsonl has 1 line", len(decisions) == 1)
    ok &= _check("watch.jsonl has 1 line", len(watch) == 1)
    ok &= _check("no SSH commands issued", client.commands == [])
    return ok


def test_block_in_dry_run_does_not_ssh(tmpdir: Path) -> bool:
    print("\n[test] BLOCK in dry_run -> DRY_RUN_BLOCK, no SSH")
    factory, client = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=True, log_dir=tmpdir) as ex:
        d = make_decision("203.0.113.30", Verdict.BLOCK)
        r = ex.handle(d)
    ok = True
    ok &= _check("outcome is DRY_RUN_BLOCK", r.outcome == ExecutorOutcome.DRY_RUN_BLOCK)
    ok &= _check("no SSH commands issued", client.commands == [],
                 detail=f"got {client.commands}")
    return ok


def test_allowlist_refusal(tmpdir: Path) -> bool:
    print("\n[test] BLOCK on allowlisted IP -> REFUSED_ALLOWLIST, no SSH")
    factory, client = make_fake_factory()
    # dry_run=False to confirm allowlist check happens BEFORE the dry_run gate.
    with BlockExecutor(factory, ALLOWLIST, dry_run=False, log_dir=tmpdir) as ex:
        # Try every allowlisted IP — none should ever cause SSH.
        for ip in ALLOWLIST:
            d = make_decision(ip, Verdict.BLOCK)
            r = ex.handle(d)
            if r.outcome != ExecutorOutcome.REFUSED_ALLOWLIST:
                print(f"  FAIL  {ip} -> {r.outcome.value}")
                return False
    ok = _check("every allowlisted IP refused", True)
    ok &= _check("no SSH commands issued", client.commands == [],
                 detail=f"got {client.commands}")
    return ok


def test_rate_limit(tmpdir: Path) -> bool:
    print("\n[test] Rate limit of 3/min: 4th real block refused")
    factory, client = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=False,
                       rate_limit_per_min=3, log_dir=tmpdir) as ex:
        outcomes = []
        for i in range(4):
            d = make_decision(f"203.0.113.{40+i}", Verdict.BLOCK)
            outcomes.append(ex.handle(d).outcome)
    ok = True
    ok &= _check("first three are REAL_BLOCK",
                 outcomes[:3] == [ExecutorOutcome.REAL_BLOCK]*3,
                 detail=f"got {[o.value for o in outcomes[:3]]}")
    ok &= _check("fourth is REFUSED_RATE_LIMIT",
                 outcomes[3] == ExecutorOutcome.REFUSED_RATE_LIMIT,
                 detail=f"got {outcomes[3].value}")
    ok &= _check("exactly 3 ipset add commands sent",
                 sum("ipset add" in c for c in client.commands) == 3,
                 detail=f"got {client.commands}")
    return ok


def test_duplicate_skipped(tmpdir: Path) -> bool:
    print("\n[test] BLOCK same IP twice -> second is SKIPPED_DUPLICATE")
    factory, client = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=False, log_dir=tmpdir) as ex:
        d = make_decision("203.0.113.50", Verdict.BLOCK)
        r1 = ex.handle(d)
        r2 = ex.handle(d)
    ok = True
    ok &= _check("first call is REAL_BLOCK", r1.outcome == ExecutorOutcome.REAL_BLOCK)
    ok &= _check("second call is SKIPPED_DUPLICATE",
                 r2.outcome == ExecutorOutcome.SKIPPED_DUPLICATE)
    ok &= _check("only one ipset add issued",
                 sum("ipset add" in c for c in client.commands) == 1,
                 detail=f"got {client.commands}")
    return ok


def test_ssh_failure_returns_failed_block(tmpdir: Path) -> bool:
    print("\n[test] ipset returns nonzero -> FAILED_BLOCK with stderr")
    factory, client = make_fake_factory(fail_with=(1, "ipset v7.15: bad value"))
    with BlockExecutor(factory, ALLOWLIST, dry_run=False, log_dir=tmpdir) as ex:
        d = make_decision("203.0.113.60", Verdict.BLOCK)
        r = ex.handle(d)
    ok = True
    ok &= _check("outcome is FAILED_BLOCK", r.outcome == ExecutorOutcome.FAILED_BLOCK)
    ok &= _check("stderr is captured in detail",
                 "ipset v7.15" in (r.detail or ""),
                 detail=f"detail={r.detail!r}")
    return ok


def test_decisions_jsonl_is_valid(tmpdir: Path) -> bool:
    print("\n[test] decisions.jsonl: every line parses as JSON with expected keys")
    factory, _ = make_fake_factory()
    with BlockExecutor(factory, ALLOWLIST, dry_run=True, log_dir=tmpdir) as ex:
        ex.handle(make_decision("203.0.113.70", Verdict.ALLOW))
        ex.handle(make_decision("203.0.113.71", Verdict.WATCH))
        ex.handle(make_decision("203.0.113.72", Verdict.BLOCK))
    lines = (tmpdir / "decisions.jsonl").read_text(encoding="utf-8").strip().splitlines()
    ok = _check("three decisions logged", len(lines) == 3)
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            ok &= _check(f"line {i} parses as JSON", False, detail=str(e))
            continue
        ok &= _check(f"line {i} has logged_at",  "logged_at" in rec)
        ok &= _check(f"line {i} has decision",   "decision"  in rec)
        ok &= _check(f"line {i} has executor",   "executor"  in rec)
        ok &= _check(f"line {i} executor.dry_run is True",
                     rec["executor"]["dry_run"] is True)
    return ok


def test_real_ssh_roundtrip() -> bool:
    """
    Live test against the actual VM. Blocks 192.0.2.1 (TEST-NET-1, reserved
    for docs, never a real client) and then cleans up.
    """
    print("\n[test] REAL SSH: block 192.0.2.1 via ipset, then remove it")
    try:
        from src.ssh_client import ssh_connection
    except Exception as e:
        print(f"  SKIP  could not import ssh_connection: {e}")
        return True  # don't fail the suite on environment issues

    test_ip = "192.0.2.1"  # TEST-NET-1, RFC 5737 — guaranteed non-routable
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        with BlockExecutor(ssh_connection, ALLOWLIST,
                           dry_run=False, rate_limit_per_min=10,
                           log_dir=tmpdir) as ex:
            d = make_decision(test_ip, Verdict.BLOCK)
            r = ex.handle(d)
            ok = _check(f"block {test_ip} -> REAL_BLOCK",
                        r.outcome == ExecutorOutcome.REAL_BLOCK,
                        detail=f"got {r.outcome.value}, detail={r.detail!r}")

            # Verify the IP is actually in the ipset on the server.
            with ssh_connection() as client:
                stdin, stdout, stderr = client.exec_command(
                    f"sudo ipset list ml_blocks | grep -E '^{test_ip} '"
                )
                out = stdout.read().decode("utf-8")
            ok &= _check(f"{test_ip} appears in ml_blocks on server",
                         test_ip in out, detail=f"ipset list grep returned: {out!r}")

            # Clean up: remove the test IP so we don't leave it in the set.
            with ssh_connection() as client:
                client.exec_command(f"sudo ipset del ml_blocks {test_ip}")
            ok &= _check("cleanup ran (ipset del issued)", True)

    return ok


# ----- Driver ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-live", action="store_true",
                        help="Skip the real-SSH test (run only fake-SSH tests).")
    args = parser.parse_args()

    all_ok = True

    fake_tests = [
        test_allow_verdict_is_noop,
        test_watch_verdict_logs_both_files,
        test_block_in_dry_run_does_not_ssh,
        test_allowlist_refusal,
        test_rate_limit,
        test_duplicate_skipped,
        test_ssh_failure_returns_failed_block,
        test_decisions_jsonl_is_valid,
    ]
    for t in fake_tests:
        with tempfile.TemporaryDirectory() as td:
            all_ok &= t(Path(td))

    if not args.no_live:
        all_ok &= test_real_ssh_roundtrip()
    else:
        print("\n[skipped] real-SSH test (--no-live)")

    print("\n" + ("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
