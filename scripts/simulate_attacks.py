"""
Phase 2C attack simulator.

Runs a diverse suite of six attack types back-to-back, recording each in the
attack manifest for ground-truth labeling.

Each attack stresses different features so the trained model is forced to
learn multidimensional decision rules:
    - SYN scan       -> port diversity + syn_only_ratio
    - FIN scan       -> fin_ratio (different flag pattern entirely)
    - UDP scan       -> udp_ratio (different protocol)
    - Slow scan      -> port diversity at low rate (rate-based heuristics fail)
    - SYN flood      -> raw packet rate to single port
    - SSH brute      -> connection rate to one common port (port 22)

Run BEFORE this:
    On Ubuntu:  sudo iptables -F && sudo iptables -A INPUT -j LOG --log-prefix "FW_LOG: "
    Optional:   sudo truncate -s 0 /var/log/kern.log   (for a clean dataset)

Usage (from project root):
    python -m scripts.simulate_attacks
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.attack_orchestrator import AttackOrchestrator


# Configuration
ATTACKER_IP   = "192.168.56.103"
TARGET_IP     = "192.168.56.102"
MANIFEST_PATH = Path(__file__).parent.parent / "data" / "attack_manifest.json"


def main():
    orch = AttackOrchestrator(
        attacker_ip=ATTACKER_IP,
        target_ip=TARGET_IP,
        manifest_path=MANIFEST_PATH,
    )

    print("=" * 60)
    print("Phase 2C — Diverse attack suite")
    print("=" * 60)
    print(f"Attacker: {ATTACKER_IP}")
    print(f"Target:   {TARGET_IP}")
    print(f"Estimated total runtime: ~12 minutes")
    print("=" * 60)

    # 1. SYN scan, full low-port range
    orch.run(
        attack_type="syn_scan",
        command=f"sudo -n nmap -sS -p 1-1024 {TARGET_IP} -Pn -T4",
        cooldown_seconds=90,
        notes="Standard nmap SYN scan, ports 1-1024, default timing T4",
    )

    # 2. FIN scan — stealth variant
    orch.run(
        attack_type="fin_scan",
        command=f"sudo -n nmap -sF -p 1-1024 {TARGET_IP} -Pn -T4",
        cooldown_seconds=90,
        notes="FIN scan — sends FIN to elicit RST from closed ports",
    )

    # 3. UDP scan — different protocol
    orch.run(
        attack_type="udp_scan",
        command=f"sudo -n nmap -sU --top-ports 50 {TARGET_IP} -Pn",
        cooldown_seconds=90,
        notes="UDP scan on top 50 UDP ports",
    )

    # 4. Slow SYN scan — rate-evasion
    orch.run(
        attack_type="slow_scan",
        command=f"sudo -n nmap -sS -p 22,80,443,3306,8080 {TARGET_IP} -Pn -T1",
        cooldown_seconds=90,
        notes="Slow SYN scan (T1 = ~15s between probes) on common ports",
    )

    # 5. SYN flood — DoS, high rate to single port
    orch.run_timed(
        attack_type="syn_flood",
        command=f"hping3 --flood -S -p 80 {TARGET_IP}",
        duration_seconds=5,
        cooldown_seconds=90,
        notes="5s SYN flood at port 80 via hping3 (rate-limited to 5s for safety)",
    )

    # 6. SSH brute force — application-layer attack
    orch.run(
        attack_type="ssh_brute",
        command=f"python3 ~/attack_tools/ssh_bruteforce.py {TARGET_IP} admin-ai 50",
        cooldown_seconds=90,
        notes="50 wrong-password SSH login attempts from Kali",
    )

    orch.save_manifest()

    print("\n" + "=" * 60)
    print("Attack suite complete.")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. python -m scripts.collect_data")
    print("  2. python -m scripts.relabel_with_manifest")
    print("\nThen inspect data/flows_labeled.csv — you should see ~10 attack flows")
    print("across 6 different attack_type values.")


if __name__ == "__main__":
    main()