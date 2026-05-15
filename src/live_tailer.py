"""
Phase 4C — Live log tailer + rolling flow aggregator.

Streams /var/log/kern.log from the Ubuntu server over SSH, parses FW_LOG
entries into packet records, buffers them per source IP, and emits completed
60-second flows as soon as their window closes.

The module is a pure "packet stream -> flow stream" converter with no
side effects. Flows are yielded to whatever consumer is hooked in
(Phase 4E will hook the decision engine + block executor).

Key design notes:
- SSH disconnects are caught and the connection is reestablished with
  exponential backoff. State (buffered packets) survives reconnects.
- Each flow is emitted ~10 seconds after its window theoretically closes,
  to absorb slight log delivery delays. Total flow-decision latency: ~70s.
- The tailer never crashes on bad lines: malformed lines are silently
  skipped. This is intentional — one bad line should not kill the agent.
"""
import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator, Optional, Callable

import pandas as pd

from src.ssh_client import ssh_connection
from src.fw_parser import parse_fw_log
from src.flow_features import _compute_flow_features


# ----------------------------------------------------------------------
# Configuration constants
# ----------------------------------------------------------------------
WINDOW_SECONDS = 60          # flow window size (must match training)
GRACE_SECONDS  = 10          # extra time we wait after a window before emitting
RECONNECT_BACKOFF_INITIAL = 2
RECONNECT_BACKOFF_MAX     = 60
TAIL_COMMAND = "sudo tail -F -n 0 /var/log/kern.log"
# -F (capital): tail by filename, survives log rotation
# -n 0: don't replay history — only stream NEW lines from this moment forward


# ----------------------------------------------------------------------
# Internal: per-IP packet buffer
# ----------------------------------------------------------------------
class _IpBuffer:
    """Buffers packets for one source IP, organized by window_start."""

    def __init__(self):
        # {window_start (datetime, floored to minute): [packet_dict, ...]}
        self.windows = defaultdict(list)

    def add(self, packet: dict):
        ts = packet["timestamp"]
        window_start = ts.replace(second=0, microsecond=0)
        # Floor to the 60-second window
        # (assumes WINDOW_SECONDS=60; revisit if we ever go smaller)
        self.windows[window_start].append(packet)

    def closed_windows(self, current_time: datetime) -> list[datetime]:
        """Return window_starts whose window+grace has fully elapsed."""
        cutoff = current_time - timedelta(seconds=WINDOW_SECONDS + GRACE_SECONDS)
        return [w for w in self.windows if w <= cutoff]

    def pop(self, window_start: datetime) -> list[dict]:
        """Remove and return packets for a closed window."""
        return self.windows.pop(window_start)

    def is_empty(self) -> bool:
        return not self.windows


# ----------------------------------------------------------------------
# Main tailer class
# ----------------------------------------------------------------------
class LiveTailer:
    """
    Stream packets from kern.log over SSH and emit completed flows.

    Usage:
        def on_flow(flow_dict):
            print(flow_dict)
        tailer = LiveTailer(on_flow_callback=on_flow)
        tailer.run()  # blocking; runs until stop() called or Ctrl-C
    """

    def __init__(self, on_flow_callback: Callable[[dict], None]):
        self.on_flow = on_flow_callback
        # {src_ip: _IpBuffer}
        self.buffers: dict[str, _IpBuffer] = defaultdict(_IpBuffer)
        # The most recent packet timestamp seen — our "current time" watermark.
        self.watermark: Optional[datetime] = None
        # Stats for monitoring
        self.stats = {
            "packets_parsed": 0,
            "packets_dropped": 0,
            "flows_emitted":  0,
            "reconnects":     0,
        }
        self._stop_flag = threading.Event()

    def stop(self):
        """Signal the run loop to exit at next iteration."""
        self._stop_flag.set()

    def run(self):
        """
        Main loop: connect, tail, parse, emit. Reconnects on disconnect.
        Blocking — runs until stop() is called or process is killed.
        """
        backoff = RECONNECT_BACKOFF_INITIAL
        print("[tailer] Starting live tail...")

        while not self._stop_flag.is_set():
            try:
                with ssh_connection() as ssh:
                    print(f"[tailer] Connected. Running: {TAIL_COMMAND}")
                    backoff = RECONNECT_BACKOFF_INITIAL  # reset on successful connect

                    stdin, stdout, stderr = ssh.exec_command(
                        TAIL_COMMAND, get_pty=False
                    )
                    self._process_stream(stdout)

                # If we got here without exception, the stream ended cleanly
                # (which shouldn't happen with tail -F, but handle gracefully).
                print("[tailer] Tail stream ended; reconnecting...")

            except Exception as e:
                print(f"[tailer] SSH/stream error: {type(e).__name__}: {e}")
                print(f"[tailer] Reconnecting in {backoff}s...")
                self.stats["reconnects"] += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX)

    def _process_stream(self, stdout):
        """Read tail output line by line and process each packet."""
        for line in iter(stdout.readline, ""):
            if self._stop_flag.is_set():
                break
            self._process_line(line)
            self._emit_closed_flows()

    def _process_line(self, line: str):
        """Parse one line and add to the appropriate buffer."""
        packet = parse_fw_log(line)
        if packet is None or packet.get("timestamp") is None:
            self.stats["packets_dropped"] += 1
            return

        self.stats["packets_parsed"] += 1

        # Update watermark (monotonic — only move forward)
        ts = packet["timestamp"]
        if self.watermark is None or ts > self.watermark:
            self.watermark = ts

        src_ip = packet["src_ip"]
        self.buffers[src_ip].add(packet)

    def _emit_closed_flows(self):
        """Check every buffer for windows that have closed, emit them."""
        if self.watermark is None:
            return

        for src_ip in list(self.buffers.keys()):
            buf = self.buffers[src_ip]
            for window_start in buf.closed_windows(self.watermark):
                packets = buf.pop(window_start)
                flow_dict = self._build_flow_dict(src_ip, window_start, packets)
                self.stats["flows_emitted"] += 1
                try:
                    self.on_flow(flow_dict)
                except Exception as e:
                    print(f"[tailer] on_flow callback error: {type(e).__name__}: {e}")
                    # Don't kill the tailer because the callback misbehaved.

            # Clean up empty buffers so memory doesn't grow indefinitely
            if buf.is_empty():
                del self.buffers[src_ip]

    def _build_flow_dict(self, src_ip: str, window_start: datetime,
                         packets: list[dict]) -> dict:
        """
        Compute flow features from a list of packets and return a dict
        compatible with the decision engine's expected feature schema.
        """
        # Reuse the EXACT same feature computation as collect_data + relabel.
        # This guarantees the live flow shape matches what the model was
        # trained on — critical for model validity.
        df = pd.DataFrame(packets)
        flow = _compute_flow_features(src_ip, window_start, df, WINDOW_SECONDS)
        # Add the src_ip and window_start that the decision engine needs
        flow["src_ip"] = src_ip
        flow["window_start"] = window_start
        return flow