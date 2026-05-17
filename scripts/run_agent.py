"""
Phase 4E — Live agent runner.

Wires the three components built in Phase 4B/4C/4D into a single live agent:

    LiveTailer ──flow──> DecisionEngine ──Decision──> BlockExecutor
       (4C)                   (4B)                       (4D)
       sees                  thinks                     acts

Usage from project root:

    # Dry run (default). Logs decisions but never modifies the firewall.
    python -m scripts.run_agent

    # Verbose dry run — also prints ALLOW verdicts (useful for debugging).
    python -m scripts.run_agent --verbose

    # ARMED. Real blocks will be issued. Use this only when you trust the model.
    python -m scripts.run_agent --arm

    # Custom rate limit and model paths.
    python -m scripts.run_agent --arm --rate-limit 10 \
        --rf-model data/models/rf_baseline.pkl \
        --if-model data/models/iforest_baseline.pkl

Press Ctrl-C to stop the agent. A summary will be printed before exit.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

# Make `src` importable when run as a script from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.block_executor import BlockExecutor, ExecutorOutcome
from src.decision_engine import DecisionEngine
from src.live_tailer import LiveTailer
from src.ssh_client import ssh_connection


# ---------------------------------------------------------------------------
# Hardcoded allowlist — the most important constant in the project.
# Mirror this exactly into the DecisionEngine and BlockExecutor.
#
# 192.168.56.1  — operator host (your Windows box, host-only adapter)
# 127.0.0.1     — loopback noise from local services
# 10.0.2.2      — VirtualBox NAT default gateway
# 10.0.2.3      — VirtualBox NAT DNS proxy (some configs use this)
#
# If you add a new "should never be blocked" IP, add it here AND remove the
# corresponding entry from `data/agent/decisions.jsonl` if it ever got blocked.
# ---------------------------------------------------------------------------
ALLOWLIST = [
    "192.168.56.1",
    "127.0.0.1",
    "10.0.2.2",
    "10.0.2.3",
]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Phase 4E — Live ML-driven IPS agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--arm", action="store_true",
        help="ARM the agent: real ipset blocks will be issued. "
             "Default is dry-run mode — BLOCK verdicts are logged but the "
             "firewall is NOT modified.",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Print every flow including ALLOW verdicts. Default prints only "
             "non-ALLOW (BLOCK, WATCH, refusals, failures).",
    )
    p.add_argument(
        "--rate-limit", type=int, default=5,
        help="Maximum REAL blocks per rolling 60s window. Default: 5.",
    )
    p.add_argument(
        "--rf-model", type=Path,
        default=Path("data/models/rf_baseline.pkl"),
        help="Path to trained RandomForest model. Default: data/models/rf_baseline.pkl",
    )
    p.add_argument(
        "--if-model", type=Path,
        default=Path("data/models/iforest_baseline.pkl"),
        help="Path to trained IsolationForest model. Default: data/models/iforest_baseline.pkl",
    )
    p.add_argument(
        "--rf-threshold", type=float, default=0.85,
        help="RF confidence threshold for BLOCK verdicts. Default: 0.85",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Pretty console output
# ---------------------------------------------------------------------------
# ANSI color codes — Windows 10+ PowerShell supports these by default.
RESET  = "\033[0m"
DIM    = "\033[2m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"

# Map outcomes to (color, glyph) for visual scanning of the live console.
_OUTCOME_STYLE = {
    ExecutorOutcome.ALLOW_NOOP:         (DIM,    "·"),
    ExecutorOutcome.WATCH_LOGGED:       (YELLOW, "?"),
    ExecutorOutcome.REFUSED_ALLOWLIST:  (CYAN,   "A"),
    ExecutorOutcome.SKIPPED_DUPLICATE:  (DIM,    "d"),
    ExecutorOutcome.REFUSED_RATE_LIMIT: (CYAN,   "R"),
    ExecutorOutcome.DRY_RUN_BLOCK:      (YELLOW, "B"),  # would-be block
    ExecutorOutcome.REAL_BLOCK:         (RED,    "X"),
    ExecutorOutcome.FAILED_BLOCK:       (RED,    "!"),
}


def format_line(decision, result, verbose: bool) -> str | None:
    """
    Return a one-line summary of (decision, result), or None if we should
    suppress this line at the current verbosity level.
    """
    # Suppress ALLOW noise unless --verbose
    if result.outcome == ExecutorOutcome.ALLOW_NOOP and not verbose:
        return None

    color, glyph = _OUTCOME_STYLE.get(result.outcome, ("", "?"))
    ts = str(decision.window_start)
    ip = decision.src_ip.ljust(15)
    outcome = result.outcome.value.ljust(20)
    rf = f"RF={decision.rf_probability:.2f}"
    if_ = f"IF={'anom' if decision.if_anomalous else 'norm'}"
    extra = ""
    if result.detail and result.outcome not in (ExecutorOutcome.ALLOW_NOOP,
                                                 ExecutorOutcome.WATCH_LOGGED):
        extra = f"  ({result.detail})"
    return f"{color}{glyph} {ts}  {ip}  {outcome}  {rf}  {if_}{extra}{RESET}"


# ---------------------------------------------------------------------------
# Run-time counters (separate from BlockExecutor's internal state because we
# want to report per-run summary even if the executor's logs span runs).
# ---------------------------------------------------------------------------
class RunStats:
    def __init__(self):
        self.outcomes: dict[str, int] = {}
        self._lock = threading.Lock()

    def record(self, outcome: ExecutorOutcome):
        with self._lock:
            self.outcomes[outcome.value] = self.outcomes.get(outcome.value, 0) + 1

    def total(self) -> int:
        return sum(self.outcomes.values())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    # --- Banner ------------------------------------------------------------
    print(BOLD + "=" * 72 + RESET)
    print(BOLD + " AI/ML Firewall IPS — Live Agent (Phase 4E)" + RESET)
    print(BOLD + "=" * 72 + RESET)
    print(f"  Mode:          {RED + 'ARMED' + RESET if args.arm else GREEN + 'DRY-RUN' + RESET}")
    print(f"  RF model:      {args.rf_model}")
    print(f"  IF model:      {args.if_model}")
    print(f"  RF threshold:  {args.rf_threshold}")
    print(f"  Rate limit:    {args.rate_limit} real blocks / 60s")
    print(f"  Verbose:       {args.verbose}")
    print(f"  Allowlist:     {', '.join(ALLOWLIST)}")
    print(BOLD + "=" * 72 + RESET)

    # --- Sanity-check model files exist before we try to load them --------
    for label, path in [("RF", args.rf_model), ("IF", args.if_model)]:
        if not path.exists():
            print(f"{RED}ERROR: {label} model not found at {path}{RESET}")
            print("Train the models first (scripts/train_ai.py, scripts/train_anomaly.py).")
            sys.exit(2)

    # --- Build the engine and executor ------------------------------------
    print("Loading models...")
    engine = DecisionEngine.from_disk(
        rf_path=args.rf_model,
        if_path=args.if_model,
        allowlist=ALLOWLIST,
        rf_confidence_threshold=args.rf_threshold,
    )
    print(f"  Loaded {len(engine.feature_columns)} features.")

    executor = BlockExecutor(
        ssh_conn_factory=ssh_connection,
        allowlist=ALLOWLIST,
        rate_limit_per_min=args.rate_limit,
        dry_run=not args.arm,
        log_dir=Path("data/agent"),
    )

    # If we're armed, sync our in-memory blocked set with whatever is already
    # in the ipset on the server. This means restarting the agent doesn't
    # cause us to redundantly try to re-block IPs whose timeouts are still
    # ticking from a previous run.
    if args.arm:
        try:
            n = executor.resync_from_server()
            print(f"  Resynced {n} IPs already in ml_blocks on server.")
        except Exception as e:
            print(f"{YELLOW}  WARNING: resync_from_server failed: {e}{RESET}")
            print(f"{YELLOW}  Continuing — duplicates will be caught by 'ipset add -exist'.{RESET}")

    stats = RunStats()

    # --- The bridge callback that wires the three components together -----
    def on_flow(flow: dict):
        try:
            decision = engine.decide(flow)
            result   = executor.handle(decision)
            stats.record(result.outcome)
            line = format_line(decision, result, args.verbose)
            if line:
                print(line, flush=True)
        except Exception as e:
            # Never let a per-flow error kill the agent.
            print(f"{RED}[agent] callback error on flow {flow.get('src_ip')}: "
                  f"{type(e).__name__}: {e}{RESET}", flush=True)

    # --- Tailer in a background thread so Ctrl-C reaches the main thread --
    tailer = LiveTailer(on_flow_callback=on_flow)

    def tailer_target():
        try:
            tailer.run()
        except Exception as e:
            print(f"{RED}[agent] tailer.run() raised: {type(e).__name__}: {e}{RESET}")

    tailer_thread = threading.Thread(target=tailer_target, name="LiveTailer", daemon=True)

    # --- Signal handling for clean shutdown -------------------------------
    shutdown_event = threading.Event()

    def request_shutdown(signum=None, frame=None):
        if not shutdown_event.is_set():
            print(f"\n{YELLOW}[agent] Shutdown requested. Stopping tailer...{RESET}")
            shutdown_event.set()
            tailer.stop()

    # SIGINT (Ctrl-C) on all platforms; SIGTERM on POSIX.
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, request_shutdown)
        except (AttributeError, ValueError):
            pass  # not all platforms allow SIGTERM handler registration

    # --- Run --------------------------------------------------------------
    print("Starting tailer. Ctrl-C to stop.")
    print(BOLD + "-" * 72 + RESET)
    started = time.time()
    tailer_thread.start()

    # Main thread parks until Ctrl-C or the tailer thread dies.
    try:
        while tailer_thread.is_alive() and not shutdown_event.is_set():
            tailer_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        # Belt and suspenders: in some environments KeyboardInterrupt arrives
        # here even with a signal handler installed.
        request_shutdown()

    # Give the tailer a moment to wind down its SSH stream.
    tailer_thread.join(timeout=5.0)
    if tailer_thread.is_alive():
        print(f"{YELLOW}[agent] Tailer didn't stop cleanly within 5s; exiting anyway.{RESET}")

    # --- Summary ----------------------------------------------------------
    duration = time.time() - started
    executor.shutdown()

    print(BOLD + "-" * 72 + RESET)
    print(BOLD + " Run summary" + RESET)
    print(BOLD + "-" * 72 + RESET)
    print(f"  Duration:           {duration:.1f}s")
    print(f"  Mode:               {'ARMED' if args.arm else 'DRY-RUN'}")
    print(f"  Tailer stats:       {tailer.stats}")
    print(f"  Total decisions:    {stats.total()}")
    if stats.outcomes:
        for outcome_name in sorted(stats.outcomes):
            print(f"    {outcome_name:.<25} {stats.outcomes[outcome_name]}")
    else:
        print("    (no flows processed)")
    print(BOLD + "=" * 72 + RESET)


if __name__ == "__main__":
    main()