"""Quick smoke test for SSH connectivity to both VMs."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ssh_client import ssh_connection, kali_connection


def run_remote(ssh, cmd: str) -> str:
    """Run a command on the remote host and return stdout."""
    stdin, stdout, stderr = ssh.exec_command(cmd)
    return stdout.read().decode().strip()


def main():
    print("Testing connection to Ubuntu server...")
    with ssh_connection() as ssh:
        hostname = run_remote(ssh, "hostname")
        ip       = run_remote(ssh, "hostname -I")
        print(f"  hostname: {hostname}")
        print(f"  IPs:      {ip}")
    print("  ✓ Ubuntu OK\n")

    print("Testing connection to Kali attacker...")
    with kali_connection() as ssh:
        hostname = run_remote(ssh, "hostname")
        ip       = run_remote(ssh, "hostname -I")
        nmap_v   = run_remote(ssh, "nmap --version | head -1")
        print(f"  hostname: {hostname}")
        print(f"  IPs:      {ip}")
        print(f"  nmap:     {nmap_v}")
    print("  ✓ Kali OK\n")

    print("Both connections working — ready for Phase 2B!")


if __name__ == "__main__":
    main()