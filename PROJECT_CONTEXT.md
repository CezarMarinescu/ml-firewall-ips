# AI_IDS_Project — Context Handoff

> **Purpose of this document:** This is a briefing for any new Claude chat session
> picking up work on this project. Paste the contents of this file as your first
> message in a new chat, along with any scripts and CSV samples relevant to the
> current task. The previous Claude does not have memory between chats — this
> document IS the memory.

---

## 1. Project goal

Build an AI/ML-powered Intrusion Prevention System (IPS) that:

1. Monitors firewall logs from a Linux server in real time
2. Detects malicious network traffic using machine learning on behavioral features
3. Automatically blocks attackers via `iptables` / `ipset`
4. Periodically retrains itself on accumulated labeled data (with human review — NOT online learning)
5. Generates reports, charts, and diagnostics about detected attacks

The user wants this to be both a working system AND a learning project — explanations
should teach networking and ML fundamentals along the way, not just dump code.

The user has fundamentals in networking (nmap, IPs, ports, TCP/UDP, MAC addresses)
and is learning more. The user is comfortable in both English and Romanian and has
chosen to continue in English.

---

## 2. Lab setup

**Three machines on a host-only VirtualBox network (`192.168.56.0/24`):**

| Role | OS | IP | User | Purpose |
|------|------|------|------|---------|
| Server | Ubuntu 24.04 | `192.168.56.102` | (see .env) | Runs iptables LOG sensor, gets attacked |
| Attacker | Kali Linux | `192.168.56.103` | (see .env) | Generates malicious traffic |
| Operator | Windows + PyCharm | host | (user) | Runs Python scripts, SSH-orchestrates everything |

**Important quirk — VirtualBox dual NIC:**

The Ubuntu VM has TWO network interfaces:
- `enp0s3` (NAT, IP `10.0.2.15`) — outbound internet, used for `apt update` etc.
- `enp0s8` (Host-Only, IP `192.168.56.102`) — VM-to-VM lab traffic

The firewall logs BOTH interfaces, so logs include real internet noise (Canonical
update servers, DNS replies from `10.0.2.3`, etc.) mixed with lab traffic. This is
tolerable as benign baseline noise but worth knowing.

**Credentials are stored in `.env`** (gitignored) — see Section 4.

---

## 3. Current project structure

```
AI_IDS_Project/
├── .venv/                          # Python virtual environment
├── data/
│   ├── .gitkeep
│   └── flows.csv                   # Output of collect_data.py
├── scripts/
│   ├── __init__.py
│   └── collect_data.py             # Phase 1 entry point
├── src/
│   ├── __init__.py
│   ├── fw_parser.py                # Parses FW_LOG lines from kern.log
│   ├── flow_features.py            # Aggregates packets into time-windowed flows
│   └── ssh_client.py               # SSH context manager using .env credentials
├── .env                            # SERVER_HOST, SERVER_USER, SERVER_PASSWORD
├── .gitignore
└── requirements.txt                # paramiko, pandas, scikit-learn, joblib, python-dotenv, numpy
```

**Files NOT yet created (planned for Phase 2+):**
- `scripts/train_ai.py` — retrained for new feature set (old version exists but obsolete)
- `scripts/ai_agent_live.py` — same, needs full rewrite for new pipeline
- `scripts/simulate_attacks.py` — Phase 2 attack orchestrator
- `scripts/generate_benign.py` — Phase 2 benign traffic generator
- `data/attack_manifest.json` — Phase 2 ground-truth labels
- Reporting/dashboard layer (Phase 6)

---

## 4. Server configuration (already done)

**iptables LOG rule active on Ubuntu server:**
```bash
sudo iptables -F
sudo iptables -A INPUT -j LOG --log-prefix "FW_LOG: "
```

**Passwordless sudo configured for specific commands** (`sudo visudo`):
```
admin-ai ALL=(ALL) NOPASSWD: /usr/bin/grep, /bin/grep, /usr/sbin/iptables, /usr/sbin/ipset
```

**Log location:** `/var/log/kern.log` — uses **modern ISO 8601 timestamps**
(`2026-04-28T19:45:41.290900+03:00`), NOT legacy syslog format. Parser handles both.

---

## 5. What's been completed — Phase 1 ✅

**Goal achieved:** Replaced per-packet ML (which was effectively a hard-coded rule)
with per-flow ML using behavioral features aggregated over 60-second windows.

**Key conceptual shift:** Old design asked "is THIS PACKET malicious?" — impossible
to answer meaningfully with 2 features. New design asks "did THIS IP behave
maliciously over the last 60 seconds?" — answerable with ~20 behavioral features.

### Features extracted (per `(src_ip, time_window)` flow):

**Volume:** `n_packets`, `packets_per_sec`, `total_bytes`, `avg_packet_size`, `std_packet_size`

**Diversity:** `unique_dst_ports`, `unique_src_ports`, `unique_protocols`, `unique_dst_ips`

**TCP flags:** `syn_ratio`, `syn_only_ratio` (★ key feature for SYN scans), `ack_ratio`, `fin_ratio`, `rst_ratio`

**Protocol mix:** `tcp_ratio`, `udp_ratio`, `icmp_ratio`

**Targeting:** `common_port_ratio` (hits to ports 22/80/443/etc), `dst_port_std`

### Current labeling — HEURISTIC (temporary, will be replaced in Phase 2)

A flow is labeled malicious (`1`) if ANY of:
- `unique_dst_ports > 20` (port scan)
- `syn_only_ratio > 0.8 AND n_packets > 10` (SYN scan/flood)
- `packets_per_sec > 50` (flooding)

**Why this is temporary:** Heuristic labels are circular for ML training. The whole
point of Phase 2 is to replace heuristics with ground-truth labels derived from a
manifest of attacks the user actually ran.

### Phase 1 results on real data

After running `nmap -p 1-1000` from Kali multiple times on different days, plus
collecting normal background traffic:
- ~19 malicious flows correctly identified (all from `192.168.56.103`, the Kali box)
- ~10 benign flows (DHCP from `0.0.0.0`, DNS from `10.0.2.3`, AWS from `54.154.251.197`,
  Canonical updates from `91.189.91.157`, etc.)
- Malicious flows show textbook nmap signature: `syn_only_ratio=1.0`, `tcp_ratio=1.0`,
  `packets_per_sec` 10-1000, `unique_dst_ports` 200-1000+

**The two classes are highly separable in feature space — almost too separable.**
Current dataset is monoculture (only nmap SYN scans as attacks, only background
noise as benign). Phase 2 fixes this.

---

## 6. Key technical decisions made (and why)

1. **Flows over packets** — A model on per-packet features can only learn "port X is
   bad," which is a rule, not ML. Flow-level features encode behavior.

2. **60-second windows** — Compromise between temporal resolution (catching short
   attacks) and statistical significance (enough packets per flow to compute
   meaningful ratios).

3. **Heuristic labels are explicitly temporary** — Phase 2 replaces with manifest-based
   ground truth. Do NOT defend or extend the heuristics; they exist only to bootstrap.

4. **Periodic retraining, NOT online learning** — User chose option (a) when offered.
   Online learning is vulnerable to model poisoning by adaptive attackers.

5. **`.env` for credentials** — Plaintext passwords in scripts were a major issue in
   the original code. SSH key auth would be better but `.env` + python-dotenv is the
   pragmatic upgrade for a lab.

6. **`ipset` with timeouts planned for blocking** — Raw `iptables -A` permanent blocks
   are dangerous (false positives lock out forever, `-A` can be shadowed by earlier
   ACCEPT rules). Phase 4 will migrate to `ipset` with TTL.

7. **Anomaly detection framing planned (Phase 3)** — Real traffic is 99%+ benign;
   binary classifiers struggle with that imbalance and can't detect novel attacks.
   IsolationForest / OneClassSVM / autoencoder being considered.

---

## 7. What's next — Phase 2 plan

**Goal:** Replace heuristic labels with ground-truth labels from a known attack manifest,
and build a diverse, realistic dataset that doesn't suffer from monoculture.

### Components to build

1. **`scripts/simulate_attacks.py`** — orchestrator that:
   - Connects via SSH to BOTH Ubuntu (to clear log, collect after) AND Kali (to run attacks)
   - Runs a sequence of varied attacks with timestamps recorded
   - Writes `data/attack_manifest.json` with `{attack_type, attacker_ip, start_ts, end_ts}` records

2. **`scripts/generate_benign.py`** — generates realistic benign traffic:
   - SSH connections that complete normally
   - HTTP requests (curl)
   - Pings (small ICMP volumes)
   - File transfers
   - Windows host → Ubuntu server, so `192.168.56.1` (or whatever the host IP is) appears as a benign source

3. **Updated `src/flow_features.py`** — add `label_flows_from_manifest(flows_df, manifest)`:
   - For each flow, check if `(src_ip, window_start)` falls inside any manifest entry
   - Label `1` if matched, `0` otherwise
   - Carry attack type as metadata column for stratified analysis later

4. **Attack types to include:**
   - SYN scan (`nmap -sS`) — already covered
   - FIN scan (`nmap -sF`)
   - NULL scan (`nmap -sN`)
   - XMAS scan (`nmap -sX`)
   - UDP scan (`nmap -sU`)
   - Slow scan (`nmap -T1`)
   - Ping flood (`hping3 --flood --icmp`)
   - SYN flood (`hping3 --flood -S`)
   - SSH brute force attempts (hydra or simple paramiko loop)
   - Slowloris if time permits

### Two open questions for the user (asked but not yet answered)

1. **Can the Windows machine SSH directly into the Kali VM?** Determines whether
   `simulate_attacks.py` can fully orchestrate from PyCharm or whether parts must
   run on Kali manually.
2. **Should attacks attempt to actually succeed (real password lists, real exploits)
   or just be detected (connection attempts that get refused)?** Recommended the
   second for cleanliness/speed; awaiting confirmation.

---

## 8. Phase 3+ roadmap (future)

- **Phase 3 — Switch to anomaly detection framing** (IsolationForest / autoencoder)
  alongside or instead of binary classification
- **Phase 4 — Safe blocking layer** with `ipset` timeouts, allowlist for the user's
  own IP, confidence threshold, decision logging
- **Phase 5 — Continuous learning pipeline** with periodic batch retraining and
  human-in-the-loop label confirmation
- **Phase 6 — Reporting dashboard** (Streamlit or Flask + Chart.js): attacks over time,
  top attacker IPs, attack type breakdown, model confidence distribution, FP review queue

---

## 9. Networking concepts the user has already been taught

(Don't re-explain unprompted; reference if needed)

- OSI/TCP-IP layer model basics
- Public vs private IP ranges
- Why VirtualBox VMs have two IPs (NAT + Host-Only)
- NAT mechanics
- TCP vs UDP differences
- TCP three-way handshake (SYN → SYN+ACK → ACK)
- TCP flags: SYN, ACK, FIN, RST, PSH, URG
- Why SYN scans are detectable (`syn_only_ratio = 1.0` because nmap never sends ACK)
- Variant scan types (FIN, NULL, XMAS, ACK)
- Common ports cheat sheet (22, 80, 443, 53, 3306, 3389, etc.)
- iptables chains (INPUT/OUTPUT/FORWARD), targets (ACCEPT/DROP/REJECT/LOG)
- Stateful vs stateless firewalls
- Brute force, SYN flood, Slowloris, MITM, ARP spoofing concepts

---

## 10. Communication style preferences

- User explicitly appreciates the teaching style — explain WHY before code
- Step-by-step instructions with explicit file paths and exact commands
- Honest pushback when the user's design has flaws (they explicitly invited this)
- Long detailed responses are welcomed when they're educational
- User catches markdown autolink artifacts in pasted code (`[parser.py](http://parser.py)`) —
  warn about these when they happen
- User runs everything in PyCharm on Windows; terminal commands should be PowerShell-friendly

---

## 11. Things to watch out for

1. **Markdown autolink leakage** — the user's chat client converts things like
   `parser.py` into `[parser.py](http://parser.py)` when pasted. Always warn the user
   to check pasted code for these.

2. **Empty DataFrame crashes** — original `collect_data.py` crashed with `KeyError: 'label'`
   when no flows were produced. Hardened `main()` now exits cleanly. Apply the same
   defensive pattern in any future scripts.

3. **kern.log timestamp format is ISO 8601** on this Ubuntu version. Parser handles
   both ISO and legacy syslog formats — don't break this when refactoring.

4. **The 201,520 packets in the user's first run** were not all from attacks — most
   were legitimate internet noise via the NAT interface. Don't assume "lots of packets
   = lots of attacks."

5. **`break` after first detection in old `ai_agent_live.py`** killed the agent
   permanently. The Phase 4 rewrite must NOT do this — just block-and-continue.

6. **`iptables -A` vs `-I`** — append vs insert at top. Blocking rules should always
   use `-I INPUT 1` to avoid being shadowed by earlier ACCEPT rules.

---

## 12. How to use this document in a new chat

Start the new chat with something like:

> Hi Claude, I'm continuing work on an AI/ML firewall project. Below is the full
> context document from my last session. Please read it carefully, then I'll tell
> you what I want to work on next. Don't start writing code until I confirm.
>
> [paste contents of PROJECT_CONTEXT.md]

Then in your second message, tell the new Claude exactly what you want to do next
(e.g. "Let's start Phase 2" or "I'm hitting a bug in collect_data.py, here's the
error..."). If the work involves code, also paste the current contents of any
relevant scripts and a few sample rows from `flows.csv`.

---

*Last updated: end of Phase 1, before Phase 2 kickoff.*
*Update this file at the end of each phase or major milestone.*
