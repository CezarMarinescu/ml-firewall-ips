"""
Phase 4F — Kill switch / unblock utility.

Single-purpose CLI tool to remove IPs from the ml_blocks ipset on the
Ubuntu server. Use cases:

  - Emergency flush during a false-positive cascade
  - Removing one specific IP that shouldn't be blocked
  - Inspecting what's currently blocked without modifying anything

Every action is logged to data/agent/unblocks.jsonl for the audit trail.

Usage from project root:

    # List what's currently in ml_blocks (no changes)
    python -m scripts.unblock_all --list

    # Remove one specific IP
    python -m scripts.unblock_all --ip 192.168.56.103

    # Flush EVERYTHING. Requires confirmation unless --yes is passed.
    python -m scripts.unblock_all
    python -m scripts.unblock_all --yes        # no prompt — for scripts
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make `src` importable when run as a script from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ssh_client import ssh_connection


IPSET_NAME = "ml_blocks"
AUDIT_LOG = Path("data/agent/unblocks.jsonl")


# ---------------------------------------------------------------------------
# Console colors (subset of run_agent.py's palette)
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
BOLD   = "\033[1m"


# ---------------------------------------------------------------------------
# SSH helpers — small wrappers around exec_command for clarity at call site
# ---------------------------------------------------------------------------
def _exec(client, cmd: str) -> tuple[int, str, str]:
    """Run `cmd` via SSH. Returns (rc, stdout, stderr)."""
    stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc  = stdout.channel.recv_exit_status()
    return rc, out, err


def list_blocked_ips(client) -> list[tuple[str, str]]:
    """
    Returns a list of (ip, timeout_string) tuples currently in ml_blocks.
    timeout_string is e.g. "3580" or "" if the entry has no timeout shown.
    """
    rc, out, err = _exec(client, f"sudo ipset list {shlex.quote(IPSET_NAME)}")
    if rc != 0:
        raise RuntimeError(f"ipset list failed (rc={rc}): {err.strip()}")

    entries: list[tuple[str, str]] = []
    in_members = False
    for line in out.splitlines():
        if line.startswith("Members:"):
            in_members = True
            continue
        if in_members:
            tokens = line.strip().split()
            if not tokens:
                continue
            ip = tokens[0]
            # Look for "timeout NNNN" pattern in remaining tokens
            timeout = ""
            for i, t in enumerate(tokens):
                if t == "timeout" and i + 1 < len(tokens):
                    timeout = tokens[i + 1]
                    break
            entries.append((ip, timeout))
    return entries


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def log_action(action: str, removed_ips: list[str], reason: str = ""):
    """Append one JSONL record to data/agent/unblocks.jsonl."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "action":    action,         # "flush", "remove_one", "list_only"
        "removed":   removed_ips,    # list of IPs actually removed
        "count":     len(removed_ips),
        "reason":    reason,
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------
def cmd_list() -> int:
    """Just show what's in ml_blocks. No mutation, no audit log entry."""
    with ssh_connection() as client:
        entries = list_blocked_ips(client)
    print(BOLD + "=" * 60 + RESET)
    print(BOLD + f" Current contents of ipset '{IPSET_NAME}'" + RESET)
    print(BOLD + "=" * 60 + RESET)
    if not entries:
        print(f"  {GREEN}(empty){RESET}")
    else:
        print(f"  {len(entries)} IP(s) currently blocked:\n")
        for ip, timeout in entries:
            t = f"timeout {timeout}s" if timeout else "(no timeout)"
            print(f"    {ip:<20} {t}")
    print(BOLD + "=" * 60 + RESET)
    return 0


def cmd_remove_one(ip: str, reason: str) -> int:
    """Remove one IP from ml_blocks. Idempotent — succeeds even if not present."""
    with ssh_connection() as client:
        # Snapshot before, so we can report whether the IP was actually there.
        before = {entry[0] for entry in list_blocked_ips(client)}
        was_present = ip in before

        rc, out, err = _exec(
            client,
            f"sudo ipset del {shlex.quote(IPSET_NAME)} {shlex.quote(ip)}",
        )

    # ipset del returns nonzero if the IP wasn't in the set. That's not really
    # an error for us — it just means there was nothing to remove.
    if rc != 0 and not was_present:
        print(f"{YELLOW}IP {ip} was not in {IPSET_NAME} — nothing to remove.{RESET}")
        log_action("remove_one", removed_ips=[], reason=reason)
        return 0
    if rc != 0:
        print(f"{RED}Failed to remove {ip} (rc={rc}): {err.strip()}{RESET}")
        return 1

    print(f"{GREEN}Removed {ip} from {IPSET_NAME}.{RESET}")
    log_action("remove_one", removed_ips=[ip], reason=reason)
    return 0


def cmd_flush(reason: str) -> int:
    """Remove all IPs from ml_blocks. The big red button."""
    with ssh_connection() as client:
        before = list_blocked_ips(client)
        before_ips = [ip for ip, _ in before]

        if not before:
            print(f"{GREEN}ml_blocks is already empty — nothing to flush.{RESET}")
            log_action("flush", removed_ips=[], reason=reason)
            return 0

        rc, out, err = _exec(client, f"sudo ipset flush {shlex.quote(IPSET_NAME)}")
        if rc != 0:
            print(f"{RED}ipset flush failed (rc={rc}): {err.strip()}{RESET}")
            return 1

        # Verify it's actually empty now.
        after = list_blocked_ips(client)

    if after:
        print(f"{RED}Flush did not empty the set — {len(after)} entries remain.{RESET}")
        for ip, timeout in after:
            print(f"    {ip} (timeout {timeout})")
        return 1

    print(f"{GREEN}Flushed {len(before_ips)} IP(s) from {IPSET_NAME}:{RESET}")
    for ip in before_ips:
        print(f"    {ip}")
    log_action("flush", removed_ips=before_ips, reason=reason)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Phase 4F — Kill switch for the ml_blocks ipset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage")[1] if "Usage" in __doc__ else "",
    )
    p.add_argument(
        "--list", action="store_true",
        help="Show current contents of ml_blocks and exit. No mutation.",
    )
    p.add_argument(
        "--ip", type=str, metavar="IP",
        help="Remove one specific IP from ml_blocks instead of flushing all.",
    )
    p.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the confirmation prompt. Required for scripted use.",
    )
    p.add_argument(
        "--reason", type=str, default="",
        help="Optional reason for the action, recorded in the audit log.",
    )
    return p.parse_args()


def main():
    args = parse_args()

    # --list is mutually exclusive with --ip and the flush default.
    if args.list:
        if args.ip:
            print(f"{RED}--list and --ip are mutually exclusive.{RESET}")
            return 2
        return cmd_list()

    if args.ip:
        # Single-IP removal. No confirmation needed — it's a targeted action.
        return cmd_remove_one(args.ip, reason=args.reason)

    # Default: full flush. Confirm unless --yes.
    if not args.yes:
        print(BOLD + "=" * 60 + RESET)
        print(BOLD + f" KILL SWITCH — about to flush ipset '{IPSET_NAME}'" + RESET)
        print(BOLD + "=" * 60 + RESET)

        # Show current state so the user knows what they're about to wipe.
        try:
            with ssh_connection() as client:
                entries = list_blocked_ips(client)
            if entries:
                print(f"  Currently blocked: {len(entries)} IP(s)")
                for ip, timeout in entries:
                    t = f"timeout {timeout}s" if timeout else ""
                    print(f"    {ip:<20} {t}")
            else:
                print(f"  {GREEN}ml_blocks is already empty.{RESET}")
                print(f"{GREEN}Nothing to do.{RESET}")
                return 0
        except Exception as e:
            print(f"{RED}Could not query ml_blocks: {e}{RESET}")
            return 1

        print()
        try:
            answer = input(f"{YELLOW}Type 'yes' to confirm flush: {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}Aborted.{RESET}")
            return 130
        if answer.lower() != "yes":
            print(f"{YELLOW}Aborted (answer was '{answer}').{RESET}")
            return 0

    return cmd_flush(reason=args.reason)


if __name__ == "__main__":
    sys.exit(main())