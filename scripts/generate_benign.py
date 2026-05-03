"""
Phase 2D — Benign traffic generator.

Generates realistic, ACTIVE benign traffic from the Windows operator host
to the Ubuntu server, recording each session in a benign_manifest.json for
ground-truth labeling.

This complements the attack suite (simulate_attacks.py) — together they
teach the model what malicious AND legitimate active traffic look like,
rather than just "attack vs idle noise".

Each generator function returns an ISO timestamp pair (start, end) and a
description for the manifest. The orchestrator wraps them with timing
metadata so we get clean ground-truth labels.

Usage (from project root):
    python -m scripts.generate_benign
"""
import sys
import time
import socket
import json
import random
import threading
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import paramiko
from src.ssh_client import ssh_connection
from src.attack_orchestrator import get_server_time


ROOT = Path(__file__).parent.parent
MANIFEST_PATH = ROOT / "data" / "benign_manifest.json"

# Configuration — read from .env via ssh_client (target server)
import os
from dotenv import load_dotenv
load_dotenv()

TARGET_HOST = os.getenv("SERVER_HOST", "192.168.56.102")
TARGET_USER = os.getenv("SERVER_USER")
TARGET_PASS = os.getenv("SERVER_PASSWORD")

# Source IP — from the Windows host's perspective, traffic to 192.168.56.102
# leaves via the host-only adapter (typically 192.168.56.1).
# We hardcode it because the Windows machine has multiple interfaces.
SOURCE_IP = "192.168.56.1"


@dataclass
class BenignRecord:
    traffic_type: str
    source_ip: str
    target_ip: str
    start_ts: str
    end_ts: str
    description: str


def _save_record(records_list, traffic_type, start_ts, end_ts, description):
    rec = BenignRecord(
        traffic_type=traffic_type,
        source_ip=SOURCE_IP,
        target_ip=TARGET_HOST,
        start_ts=start_ts.isoformat(),
        end_ts=end_ts.isoformat(),
        description=description,
    )
    records_list.append(rec)
    print(f"  ✓ {traffic_type}: {description}")


# ============================================================
# Traffic generators
# ============================================================

def gen_ssh_session(records):
    """Open SSH, run a few commands, close. Realistic admin session."""
    print("\n[gen] SSH session with commands...")
    start = get_server_time()
    with ssh_connection() as ssh:
        for cmd in ["uptime", "df -h", "ls /var/log", "whoami", "free -m"]:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stdout.read()
            time.sleep(0.5)
    end = get_server_time()
    _save_record(records, "ssh_session", start, end, "SSH login + 5 commands + logout")


def gen_http_get_burst(records, n_requests=20):
    """Multiple curl-equivalent HTTP GETs to nginx."""
    print(f"\n[gen] HTTP GET burst ({n_requests} requests)...")
    start = get_server_time()
    for i in range(n_requests):
        try:
            with socket.create_connection((TARGET_HOST, 80), timeout=2) as s:
                req = (
                    f"GET /test.json HTTP/1.1\r\n"
                    f"Host: {TARGET_HOST}\r\n"
                    f"User-Agent: BenignTrafficGen/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                s.sendall(req)
                _ = s.recv(4096)  # read response (don't care about content)
        except (socket.error, socket.timeout) as e:
            print(f"    request {i} failed: {e}")
        time.sleep(random.uniform(0.1, 0.5))  # human-like pacing
    end = get_server_time()
    _save_record(records, "http_get", start, end, f"{n_requests} HTTP GETs to /test.json")


def gen_ping_burst(records, count=20):
    """ICMP echo requests via system ping command."""
    print(f"\n[gen] Ping burst ({count} packets)...")
    import subprocess
    start = get_server_time()
    # Windows ping syntax: -n count
    subprocess.run(
        ["ping", "-n", str(count), TARGET_HOST],
        capture_output=True, text=True, timeout=60,
    )
    end = get_server_time()
    _save_record(records, "ping_burst", start, end, f"{count} ICMP echo requests")


def gen_file_transfer(records, size_kb=500):
    """Upload a temp file via SFTP, then delete it."""
    print(f"\n[gen] File transfer ({size_kb} KB via SFTP)...")
    # Create a temp file with random data
    local_tmp = ROOT / "data" / "_tmp_upload.bin"
    local_tmp.parent.mkdir(parents=True, exist_ok=True)
    with open(local_tmp, "wb") as f:
        f.write(random.randbytes(size_kb * 1024))

    start = get_server_time()
    with ssh_connection() as ssh:
        sftp = ssh.open_sftp()
        remote_path = "/tmp/_benign_upload.bin"
        sftp.put(str(local_tmp), remote_path)
        sftp.remove(remote_path)
        sftp.close()
    end = get_server_time()

    local_tmp.unlink()  # clean up local temp file
    _save_record(records, "file_xfer", start, end, f"SFTP upload+delete of {size_kb} KB file")


def gen_dns_lookups(records, n=10):
    """
    DNS-style UDP traffic to the server. The server isn't a DNS server,
    but we can send well-formed DNS queries to port 53; they'll generate
    UDP traffic and ICMP unreachable responses. Realistic 'closed UDP port'
    behavior.
    """
    print(f"\n[gen] UDP probe burst ({n} packets to port 53)...")
    start = get_server_time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    # Minimal DNS query for "example.com A"
    dns_query = bytes.fromhex(
        "abcd"          # transaction id
        "0100"          # flags: standard query, recursion desired
        "0001"          # questions: 1
        "0000"          # answers: 0
        "0000"          # authority: 0
        "0000"          # additional: 0
        "076578616d706c6503636f6d00"  # "example.com"
        "0001"          # type A
        "0001"          # class IN
    )
    for _ in range(n):
        try:
            sock.sendto(dns_query, (TARGET_HOST, 53))
            try: sock.recvfrom(512)
            except socket.timeout: pass
        except socket.error:
            pass
        time.sleep(random.uniform(0.2, 0.6))
    sock.close()
    end = get_server_time()
    _save_record(records, "dns_query", start, end, f"{n} DNS queries to port 53")


def gen_mixed_concurrent(records, duration_seconds=30):
    """
    Multiple traffic types running concurrently — realistic multitasking.
    One thread does HTTP, another does pings, another does small SSH commands.
    All recorded as a single 'mixed' session for labeling.
    """
    print(f"\n[gen] Mixed concurrent traffic ({duration_seconds}s)...")
    start = get_server_time()
    stop_flag = threading.Event()

    def http_loop():
        while not stop_flag.is_set():
            try:
                with socket.create_connection((TARGET_HOST, 80), timeout=2) as s:
                    s.sendall(f"GET /test.json HTTP/1.1\r\nHost: {TARGET_HOST}\r\nConnection: close\r\n\r\n".encode())
                    s.recv(4096)
            except socket.error:
                pass
            time.sleep(random.uniform(0.5, 1.5))

    def ssh_loop():
        try:
            with ssh_connection() as ssh:
                while not stop_flag.is_set():
                    stdin, stdout, stderr = ssh.exec_command("uptime")
                    stdout.read()
                    time.sleep(random.uniform(2, 4))
        except Exception as e:
            print(f"    ssh_loop error: {e}")

    threads = [
        threading.Thread(target=http_loop, daemon=True),
        threading.Thread(target=ssh_loop,  daemon=True),
    ]
    for t in threads:
        t.start()

    time.sleep(duration_seconds)
    stop_flag.set()
    for t in threads:
        t.join(timeout=5)

    end = get_server_time()
    _save_record(records, "mixed", start, end, f"{duration_seconds}s of concurrent SSH+HTTP")


# ============================================================
# Main orchestration
# ============================================================

def save_manifest(records):
    """Append new records to existing manifest (or create it)."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if MANIFEST_PATH.exists():
        with open(MANIFEST_PATH) as f:
            existing = json.load(f)
    all_records = existing + [asdict(r) for r in records]
    with open(MANIFEST_PATH, "w") as f:
        json.dump(all_records, f, indent=2)
    print(f"\n[manifest] Saved {len(records)} new records "
          f"({len(all_records)} total) to {MANIFEST_PATH}")


def cooldown(seconds=90):
    print(f"\n[cooldown] {seconds}s before next session...")
    time.sleep(seconds)


def main():
    if not all([TARGET_USER, TARGET_PASS]):
        print("ERROR: SERVER_USER/SERVER_PASSWORD not in .env")
        return

    print("=" * 60)
    print("Phase 2D — Benign traffic generator")
    print("=" * 60)
    print(f"Source:  {SOURCE_IP} (Windows host)")
    print(f"Target:  {TARGET_HOST} (Ubuntu)")
    print(f"Estimated runtime: ~12 minutes")
    print("=" * 60)

    records = []

    gen_ssh_session(records)
    cooldown()

    gen_http_get_burst(records, n_requests=25)
    cooldown()

    gen_ping_burst(records, count=20)
    cooldown()

    gen_file_transfer(records, size_kb=500)
    cooldown()

    gen_dns_lookups(records, n=15)
    cooldown()

    gen_mixed_concurrent(records, duration_seconds=30)
    # no final cooldown — last session

    save_manifest(records)

    print("\n" + "=" * 60)
    print("Benign traffic generation complete.")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. python -m scripts.collect_data")
    print("  2. python -m scripts.relabel_with_manifest")


if __name__ == "__main__":
    main()