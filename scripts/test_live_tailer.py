"""
Smoke test for the live tailer.

Connects to Ubuntu, tails kern.log in real time, and prints a summary
every time a flow window closes. NO firewall side effects.

Run this, then in a separate terminal generate some traffic:
    From your operator:  curl http://192.168.56.102/test.json
    From Kali:           nmap -p 1-100 192.168.56.102

You should see flow events appear here as the windows close (~70s
after the traffic).

Stop with Ctrl-C.
"""
import sys
import signal
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.live_tailer import LiveTailer


def on_flow(flow: dict):
    """Called once per completed flow. Pretty-print a summary."""
    print(
        f"[flow] {flow['window_start'].strftime('%H:%M:%S')} "
        f"src={flow['src_ip']:<16} "
        f"n_pkts={flow['n_packets']:>5} "
        f"ports={flow['unique_dst_ports']:>4} "
        f"syn_only={flow['syn_only_ratio']:.2f} "
        f"tcp={flow['tcp_ratio']:.2f} "
        f"udp={flow['udp_ratio']:.2f}"
    )


def main():
    print("Phase 4C — Live tailer smoke test")
    print("Press Ctrl-C to stop.\n")

    tailer = LiveTailer(on_flow_callback=on_flow)

    # Graceful shutdown on Ctrl-C
    def handle_sigint(signum, frame):
        print("\n[main] SIGINT received, stopping tailer...")
        tailer.stop()

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        tailer.run()
    finally:
        print("\n[main] Stopped.")
        print(f"[main] Stats: {tailer.stats}")


if __name__ == "__main__":
    main()