"""
Parser for iptables FW_LOG lines from /var/log/kern.log.

A typical line looks like:
Nov  4 12:34:56 ubuntu kernel: [12345.678] FW_LOG: IN=enp0s3 OUT=
MAC=... SRC=192.168.56.103 DST=192.168.56.102 LEN=60 TOS=0x00
PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=80
WINDOW=64240 RES=0x00 SYN URGP=0
"""
import re
from datetime import datetime
from typing import Optional

# Compile regexes once at module load — much faster than recompiling per line
_PATTERNS = {
    "src_ip":   re.compile(r"SRC=([\d\.]+)"),
    "dst_ip":   re.compile(r"DST=([\d\.]+)"),
    "protocol": re.compile(r"PROTO=(\w+)"),
    "src_port": re.compile(r"SPT=(\d+)"),
    "dst_port": re.compile(r"DPT=(\d+)"),
    "length":   re.compile(r"LEN=(\d+)"),
    "ttl":      re.compile(r"TTL=(\d+)"),
}

# TCP flags appear as bare words in the log (SYN, ACK, FIN, RST, PSH, URG)
_TCP_FLAGS = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]


def parse_fw_log(line: str) -> Optional[dict]:
    """
    Parse a single FW_LOG line into a dict of fields.
    Returns None if the line is not a valid FW_LOG entry.
    """
    if "FW_LOG" not in line:
        return None

    # We require at minimum SRC and PROTO to be present
    src_match = _PATTERNS["src_ip"].search(line)
    proto_match = _PATTERNS["protocol"].search(line)
    if not (src_match and proto_match):
        return None

    record = {
        "timestamp":  _extract_timestamp(line),
        "src_ip":     src_match.group(1),
        "dst_ip":     _extract(line, "dst_ip"),
        "protocol":   proto_match.group(1),
        "src_port":   _extract_int(line, "src_port"),
        "dst_port":   _extract_int(line, "dst_port"),
        "length":     _extract_int(line, "length"),
        "ttl":        _extract_int(line, "ttl"),
    }

    # TCP flags: 1 if the flag word appears in the line, else 0
    for flag in _TCP_FLAGS:
        # Word-boundary match so "SYN" doesn't match inside "SYNC" etc.
        record[f"flag_{flag.lower()}"] = 1 if re.search(rf"\b{flag}\b", line) else 0

    return record


def _extract(line: str, field: str) -> Optional[str]:
    m = _PATTERNS[field].search(line)
    return m.group(1) if m else None


def _extract_int(line: str, field: str) -> int:
    m = _PATTERNS[field].search(line)
    return int(m.group(1)) if m else 0


def _extract_timestamp(line: str) -> Optional[datetime]:
    """
    Parse the timestamp at the start of a kern.log line.
    Handles both formats:
      - Modern ISO 8601: '2026-04-30T14:23:11.123456+03:00'
      - Legacy syslog:   'Nov  4 12:34:56' (no year, assume current)
    Returns None if neither format matches.
    """
    # Try ISO 8601 first (modern Ubuntu)
    iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if iso_match:
        try:
            return datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

    # Fall back to legacy syslog format ('Nov  4 12:34:56')
    legacy_match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if legacy_match:
        try:
            ts_str = f"{datetime.now().year} {legacy_match.group(1)}"
            return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return None