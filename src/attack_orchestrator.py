"""
Attack orchestration framework for Phase 2.

Runs attacks on Kali via SSH while recording precise start/end timestamps
(as seen by the Ubuntu server's clock) into an attack manifest. The manifest
is later used for ground-truth labeling of flows in flow_features.py.

Design notes:
- All timestamps are server-clock (Ubuntu) to match kern.log timestamps.
- Each attack returns an AttackRecord describing what was run, by whom, when.
- The orchestrator is attack-type-agnostic; concrete attacks live in
  scripts/simulate_attacks.py and only need to provide a command string.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import json
import time

from src.ssh_client import ssh_connection, kali_connection


@dataclass
class AttackRecord:
    """One entry in the attack manifest — a single attack run."""
    attack_type: str          # e.g. "syn_scan", "ssh_brute"
    attacker_ip: str          # Kali's IP (source of malicious packets)
    target_ip: str            # Ubuntu's IP (destination)
    start_ts: str             # ISO 8601 string, server-clock
    end_ts: str               # ISO 8601 string, server-clock
    command: str              # exact shell command run on Kali
    notes: Optional[str] = None  # freeform: ports scanned, # of attempts, etc.


def get_server_time() -> datetime:
    """
    Return the Ubuntu server's current time as a datetime.
    Uses ISO 8601 from `date -Iseconds` so it matches kern.log format.
    """
    with ssh_connection() as ssh:
        stdin, stdout, stderr = ssh.exec_command("date -Iseconds")
        ts_str = stdout.read().decode().strip()
    # date -Iseconds gives e.g. '2026-05-02T14:23:11+03:00'
    # datetime.fromisoformat handles this in Python 3.11+
    return datetime.fromisoformat(ts_str).replace(tzinfo=None)  # drop tz for simpler matching


def run_kali_command(command: str, timeout: int = 300) -> tuple[int, str, str]:
    """
    Execute a command on Kali via SSH and return (exit_code, stdout, stderr).

    timeout caps how long we wait — important so a hung attack doesn't
    block the whole orchestrator forever.
    """
    with kali_connection() as ssh:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
    return exit_code, out, err


class AttackOrchestrator:
    """
    Runs attacks and accumulates AttackRecord entries.
    Call save_manifest() at the end to write to disk.
    """

    def __init__(self, attacker_ip: str, target_ip: str,
                 manifest_path: Path):
        self.attacker_ip = attacker_ip
        self.target_ip   = target_ip
        self.manifest_path = manifest_path
        self.records: list[AttackRecord] = []

    def run(self, attack_type: str, command: str,
            cooldown_seconds: int = 10,
            notes: Optional[str] = None) -> AttackRecord:
        """
        Run one attack on Kali, time it, record it.

        cooldown_seconds: idle time AFTER the attack before returning.
        This separates this attack's flows from the next attack's flows in
        the time domain, which makes labeling cleaner.
        """
        print(f"\n[orchestrator] Starting attack: {attack_type}")
        print(f"[orchestrator] Command: {command}")

        start_ts = get_server_time()
        print(f"[orchestrator] Start (server time): {start_ts.isoformat()}")

        exit_code, stdout, stderr = run_kali_command(command)

        end_ts = get_server_time()
        print(f"[orchestrator] End   (server time): {end_ts.isoformat()}")
        duration = (end_ts - start_ts).total_seconds()
        print(f"[orchestrator] Duration: {duration:.1f}s, exit code: {exit_code}")

        if exit_code != 0:
            # Some attacks (hping3 floods) intentionally don't exit cleanly when killed.
            # We log a warning but still record the attack.
            print(f"[orchestrator] WARNING: non-zero exit. stderr tail: {stderr[-200:]!r}")

        record = AttackRecord(
            attack_type=attack_type,
            attacker_ip=self.attacker_ip,
            target_ip=self.target_ip,
            start_ts=start_ts.isoformat(),
            end_ts=end_ts.isoformat(),
            command=command,
            notes=notes,
        )
        self.records.append(record)

        if cooldown_seconds > 0:
            print(f"[orchestrator] Cooldown {cooldown_seconds}s...")
            time.sleep(cooldown_seconds)

        return record

    def run_timed(self, attack_type: str, command: str,
                  duration_seconds: int,
                  cooldown_seconds: int = 10,
                  notes: Optional[str] = None) -> AttackRecord:
        """
        Run an attack on Kali for a fixed duration, then kill it.

        Use this for attacks that don't self-terminate (e.g. hping3 --flood).
        Wraps the command in `timeout` so it gets killed cleanly.
        """
        # GNU `timeout` sends SIGTERM after N seconds, SIGKILL 5s later if needed.
        # `--preserve-status` so we get the underlying tool's exit code, not 124.
        wrapped = f"sudo -n timeout --preserve-status {duration_seconds} {command}"
        return self.run(attack_type, wrapped,
                        cooldown_seconds=cooldown_seconds, notes=notes)


    def save_manifest(self):
        """Write all collected records to manifest_path as JSON."""
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        # If a manifest already exists, append rather than overwrite
        existing = []
        if self.manifest_path.exists():
            with open(self.manifest_path) as f:
                existing = json.load(f)

        all_records = existing + [asdict(r) for r in self.records]

        with open(self.manifest_path, "w") as f:
            json.dump(all_records, f, indent=2)

        print(f"\n[orchestrator] Saved {len(self.records)} new records "
              f"({len(all_records)} total) to {self.manifest_path}")


