# AI_IDS_Project — Context Handoff

> **Purpose of this document:** This is a briefing for any new Claude chat session
> picking up work on this project. Paste the contents of this file as your first
> message in a new chat, along with any scripts and CSV samples relevant to the
> current task. The previous Claude does not have memory between chats — this
> document IS the memory.
>
> **This file is committed to a public GitHub repo, so it MUST NOT contain
> real credentials.** All credentials live only in `.env` (gitignored).

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
and is comfortable in both English and Romanian. Conversation is in English.

**GitHub:** https://github.com/CezarMarinescu/ml-firewall-ips (public)

---

## 2. Lab setup

**Three machines on a host-only VirtualBox network (`192.168.56.0/24`):**

| Role | OS | IP | Purpose |
|------|------|------|---------|
| Server | Ubuntu 24.04 | `192.168.56.102` | Runs iptables LOG sensor, gets attacked. Now also runs **nginx** on port 80 (added Phase 2D). |
| Attacker | Kali Linux | `192.168.56.103` | Generates malicious traffic. SSH server enabled (port 22). |
| Operator | Windows + PyCharm | host (`192.168.56.1` on host-only adapter) | Runs Python scripts, SSH-orchestrates everything, also generates benign traffic |

Credentials for both VMs are in `.env` (gitignored). See `.env.example` in repo
for the variable structure.

**Important quirk — VirtualBox dual NIC on Ubuntu:**

The Ubuntu VM has TWO network interfaces:
- `enp0s3` (NAT, IP `10.0.2.15`) — outbound internet, used for `apt update` etc.
- `enp0s8` (Host-Only, IP `192.168.56.102`) — VM-to-VM lab traffic

The firewall logs BOTH interfaces, so logs include real internet noise (Canonical
update servers, DNS replies from `10.0.2.3`, AWS heartbeats, CDN responses) mixed
with lab traffic. This is desirable as benign baseline noise but worth knowing.

**Localhost noise:** `127.0.0.1` traffic appears in logs because nginx and other
local services chatter on the loopback. **Important:** Phase 4's blocking logic
MUST exclude 127.0.0.1, the operator IP (192.168.56.1), and probably the NAT
gateway (10.0.2.x) from blocking — see Section 11.

---

## 3. Current project structure

```
AI_IDS_Project/
├── .venv/                          # Python virtual environment (gitignored)
├── data/                           # All gitignored
│   ├── flows.csv                   # Raw flow output of collect_data
│   ├── flows_labeled.csv           # Flows with manifest-based labels
│   ├── attack_manifest.json        # Ground-truth attack timestamps
│   └── benign_manifest.json        # Ground-truth benign-active session timestamps
├── scripts/
│   ├── __init__.py
│   ├── collect_data.py             # SSH to server, parse logs, build flows
│   ├── simulate_attacks.py         # Phase 2C — orchestrate attack suite from Kali
│   ├── generate_benign.py          # Phase 2D — generate benign traffic from Windows host
│   ├── relabel_with_manifest.py    # Re-label existing flows.csv from manifests
│   └── test_connections.py         # SSH smoke test for both VMs
├── src/
│   ├── __init__.py
│   ├── fw_parser.py                # Parse FW_LOG lines (handles ISO 8601 + legacy)
│   ├── flow_features.py            # Aggregate packets into flows, label from manifests
│   ├── attack_orchestrator.py      # AttackOrchestrator class + server-clock timing
│   └── ssh_client.py               # SSH context managers (ssh_connection, kali_connection)
├── .env                            # SECRETS — gitignored
├── .env.example                    # Sanitized template (in repo)
├── .gitignore
├── LICENSE                         # MIT
├── PROJECT_CONTEXT.md              # this file
├── README.md                       # Public-facing project description
└── requirements.txt                # paramiko, pandas, scikit-learn, joblib, python-dotenv, numpy
```

**Files NOT yet created (planned):**
- `scripts/train_ai.py` — needs full rewrite for new feature set (old version was deleted)
- `scripts/ai_agent_live.py` — same, full rewrite for Phase 4
- Any model files (`*.pkl`)
- Reporting/dashboard layer (Phase 6)

---

## 4. Server-side configuration (already done)

**iptables LOG rule active on Ubuntu server:**
```bash
sudo iptables -F
sudo iptables -A INPUT -j LOG --log-prefix "FW_LOG: "
```

**Passwordless sudo on Ubuntu (`sudo visudo`):**
```
admin-ai ALL=(ALL) NOPASSWD: /usr/bin/grep, /bin/grep, /usr/sbin/iptables, /usr/sbin/ipset
```

**Passwordless sudo on Kali (`sudo visudo`):**
```
attacker ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/hping3, /usr/bin/hydra, /usr/bin/timeout
```

**Kali tools installed:** nmap, hping3, hydra, paramiko (Python).

**Kali helper script:** `~/attack_tools/ssh_bruteforce.py` — paramiko-based brute
force simulator used by `simulate_attacks.py`.

**Ubuntu services running:** sshd, nginx (with `/var/www/html/test.json` test endpoint).

**Log location:** `/var/log/kern.log` — uses **modern ISO 8601 timestamps**
(`2026-04-28T19:45:41.290900+03:00`), NOT legacy syslog format. Parser handles both.

---

## 5. What's been completed

### ✅ Phase 1 — Flow-based feature extraction

Replaced per-packet ML (which was effectively a hard-coded rule) with per-flow ML
using behavioral features aggregated over 60-second windows.

**Key features extracted per `(src_ip, time_window)` flow:**
- **Volume:** `n_packets`, `packets_per_sec`, `total_bytes`, `avg_packet_size`, `std_packet_size`
- **Diversity:** `unique_dst_ports`, `unique_src_ports`, `unique_protocols`, `unique_dst_ips`
- **TCP flags:** `syn_ratio`, `syn_only_ratio` (★ key for SYN scans), `ack_ratio`, `fin_ratio`, `rst_ratio`
- **Protocol mix:** `tcp_ratio`, `udp_ratio`, `icmp_ratio`
- **Targeting:** `common_port_ratio`, `dst_port_std`

### ✅ Phase 2A — SSH connectivity to both VMs

- `src/ssh_client.py` provides `ssh_connection()` and `kali_connection()` context managers
- Both VMs reachable from Windows host via SSH using credentials in `.env`
- Passwordless sudo configured on both VMs for orchestrator commands

### ✅ Phase 2B — Attack orchestrator + manifest format

- `src/attack_orchestrator.py` with `AttackOrchestrator` class
- `get_server_time()` queries Ubuntu's clock so manifest timestamps match kern.log
- `run()` for self-terminating attacks, `run_timed()` for floods
- `data/attack_manifest.json` schema:
  ```json
  {"attack_type": "...", "attacker_ip": "...", "target_ip": "...",
   "start_ts": "ISO8601", "end_ts": "ISO8601", "command": "...", "notes": "..."}
  ```

### ✅ Phase 2C — Diverse attack suite (6 types)

Each attack stresses different features so the model must learn multi-dimensional rules:

| Attack | Tool | Stresses |
|--------|------|----------|
| `syn_scan` | `nmap -sS -p 1-1024` | port diversity + syn_only_ratio |
| `fin_scan` | `nmap -sF -p 1-1024` | fin_ratio (different flag pattern) |
| `udp_scan` | `nmap -sU --top-ports 50` | udp_ratio (different protocol) |
| `slow_scan` | `nmap -sS -T1` (5 ports) | port diversity at low rate |
| `syn_flood` | `hping3 --flood -S` (5s) | raw packet rate |
| `ssh_brute` | paramiko, 50 wrong passwords | rate to single common port |

**Cooldowns are 90 seconds** between attacks — empirically required to keep each
attack in its own 60-second window. (30-second cooldowns caused window collisions.)

### ✅ Phase 2D — Benign traffic generator (6 types)

Generates *active* benign traffic from Windows host so the "benign" class isn't
just background idle noise:

| Traffic | Method | Contrast example |
|---------|--------|------------------|
| `ssh_session` | paramiko, 5 commands | vs ssh_brute (both port 22) |
| `http_get` | raw socket, 25 GETs to nginx | vs port scans (real TCP convo) |
| `ping_burst` | system `ping -n 20` | vs UDP/ICMP floods |
| `file_xfer` | SFTP upload+delete (500 KB) | vs SYN flood (high TCP volume) |
| `dns_query` | UDP probes to port 53 | vs UDP scan (legitimate UDP) |
| `mixed` | Concurrent threaded SSH+HTTP | realistic multitasking |

90-second cooldowns between each. Same `get_server_time()` used for clock consistency.

### Manifest-based labeler (improved twice during Phase 2)

`label_flows_from_manifest()` in `src/flow_features.py` now handles BOTH manifests:
- Flows matching attack manifest → `label=1`, `attack_type=<type>`
- Flows matching benign manifest → `label=0`, `attack_type='benign_active'`, `traffic_type=<type>`
- Other flows → `label=0`, `attack_type='benign_idle'`

Multi-attack windows use **greatest time-overlap wins** instead of "last wins".
Both `all_attack_types` and `all_traffic_types` columns track all matches for debugging.

### Latest dataset state (after one full Phase 2 run)

- 65 total flows from one ~25-minute session
- 10 malicious (all 6 attack types represented)
- 9 benign-active (all 6 traffic types represented)
- 46 benign-idle (background noise)

For Phase 3, recommend running the full pipeline 2-3 more times to bulk up to
~150-200 flows for proper train/test splits.

---

## 6. Key technical decisions made (and why)

1. **Flows over packets** — A model on per-packet features can only learn "port X is
   bad," which is a rule, not ML. Flow-level features encode behavior.

2. **60-second windows** — Compromise between temporal resolution and statistical
   significance. Slow_scan deliberately spans multiple windows to teach the model
   that attacks can fragment across windows.

3. **Manifest-based labeling, not heuristic** — Ground truth from "we ran this
   attack at this time" is far more reliable than "this looks weird so probably bad".
   Heuristics introduced false positives on legitimate high-throughput traffic.

4. **Three-tier labels (malicious / benign_active / benign_idle)** — Lets us
   evaluate the model's behavior on realistic active traffic separately from idle
   noise. A model that correctly handles `benign_idle` but blocks `benign_active`
   is useless in production.

5. **Periodic retraining, NOT online learning** — User chose option (a). Online
   learning is vulnerable to model poisoning by adaptive attackers.

6. **`.env` for credentials** — Plaintext passwords in scripts were a major issue
   in the original code. SSH key auth would be even better but `.env` + python-dotenv
   is the pragmatic upgrade for a lab.

7. **`ipset` with timeouts planned for blocking (Phase 4)** — Raw `iptables -A`
   permanent blocks are dangerous (false positives lock out forever, `-A` can be
   shadowed by earlier ACCEPT rules). Phase 4 will migrate to `ipset` with TTL
   and an allowlist for operator/localhost.

8. **Anomaly detection framing planned (Phase 3)** — Real traffic is heavily skewed
   toward benign; binary classifiers struggle and can't detect novel attacks.
   IsolationForest / OneClassSVM / autoencoder being considered, possibly alongside
   a supervised classifier.

9. **Server-clock timestamps in manifests** — All manifest timestamps come from
   `date -Iseconds` on Ubuntu, NOT Python's local clock, because kern.log uses
   the server's clock. Even small clock skew between Windows and Ubuntu would
   misalign labels.

---

## 7. What's next — Phase 3 plan (paused, awaiting user task)

**Goal:** Train an actual ML model on the now-clean dataset and evaluate it properly.

### Components to build

1. **`scripts/train_ai.py`** — full rewrite:
   - Load `flows_labeled.csv`
   - Drop non-feature columns (src_ip, window_start, attack_type, traffic_type, etc.)
   - Stratified train/test split (preserve attack-type ratios)
   - Train multiple models in parallel: RandomForest baseline, IsolationForest
     anomaly detector, possibly XGBoost
   - Evaluate with proper metrics: precision, recall, F1, confusion matrix per
     attack type (NOT just overall accuracy — useless for imbalanced data)
   - Save best model + a metadata JSON describing training set, version, metrics
   - Save feature importance plots

2. **`src/model_io.py`** — load/save with versioning, schema checks (so a model
   trained on 20 features doesn't silently fail when the feature set changes).

3. **Cross-validation by attack type** — train on 5 attack types, evaluate on the
   6th, to test generalization to unseen attacks. This is the real-world question:
   can it catch attacks it wasn't trained on?

4. **A "model report" output** — text + CSV summary of model performance, for
   inclusion in PROJECT_CONTEXT updates.

### Recommended dataset prep before training

- Run `simulate_attacks.py` 2-3 more times across different days
- Run `generate_benign.py` 2-3 more times
- Aim for ~30-50 examples per attack type, ~30-50 per benign-active type, plus
  the natural accumulation of benign_idle flows
- Then train

---

## 8. Phase 4+ roadmap (future)

- **Phase 4 — Safe blocking layer** with `ipset` timeouts, hardcoded allowlist for
  operator IP / 127.0.0.1 / NAT gateway, confidence threshold for blocking,
  decision logging to file
- **Phase 5 — Continuous learning pipeline** with periodic batch retraining and
  human-in-the-loop label confirmation
- **Phase 6 — Reporting dashboard** (Streamlit or Flask + Chart.js): attacks over
  time, top attacker IPs, attack-type breakdown, model confidence distribution,
  false-positive review queue
- **Phase 7 (optional, later)** — post-compromise detection: simulating successful
  attacks and detecting lateral movement / exfiltration patterns

---

## 9. Networking concepts the user has been taught

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

User has NOT yet been formally taught:
- ML fundamentals (precision/recall, train/test, overfitting, etc.) —
  introduce these gradually in Phase 3
- ipset semantics — introduce in Phase 4

---

## 10. Communication style preferences

- User explicitly appreciates the teaching style — explain WHY before code
- Step-by-step instructions with explicit file paths and exact commands
- Honest pushback when the user's design has flaws (they explicitly invited this)
- Long detailed responses are welcomed when they're educational
- User catches markdown autolink artifacts in pasted code (`[parser.py](http://parser.py)`) —
  warn about these when they happen
- User runs everything in PyCharm on Windows; terminal commands should be PowerShell-friendly
- **The user explicitly asked to be notified when Phase 2 was complete** before
  Claude moves to Phase 3 — they had another task to insert. Always honor explicit
  pause requests like this.

---

## 11. Things to watch out for

1. **Markdown autolink leakage** — the user's chat client converts things like
   `parser.py` into `[parser.py](http://parser.py)` when pasted. Always warn the user
   to check pasted code for these.

2. **Empty DataFrame crashes** — original `collect_data.py` crashed with
   `KeyError: 'label'` when no flows were produced. Hardened `main()` exits cleanly.
   Apply the same defensive pattern in any future scripts.

3. **kern.log timestamp format is ISO 8601** on this Ubuntu version. Parser handles
   both ISO and legacy syslog formats — don't break this when refactoring.

4. **Background internet noise** in logs (Canonical update servers, AWS, CDNs) —
   most flows are this, not attacks. Don't assume "lots of packets = lots of attacks."

5. **`break` after first detection in old `ai_agent_live.py`** killed the agent
   permanently. Phase 4 rewrite must NOT do this — block-and-continue, never exit.

6. **`iptables -A` vs `-I`** — append vs insert at top. Blocking rules should always
   use `-I INPUT 1` to avoid being shadowed by earlier ACCEPT rules.

7. **Localhost (127.0.0.1) and operator IP (192.168.56.1) and NAT gateway (10.0.2.x)
   MUST be on a permanent allowlist in Phase 4** — they appear in logs and can
   trigger high-rate heuristics, but blocking them would break the server / lock
   the user out / kill VirtualBox networking.

8. **Cooldowns between orchestrated sessions must be ≥90s** — shorter cooldowns
   cause attack/benign sessions to share 60-second windows and confuse labeling.

9. **`hping3 --flood` and `nmap -sS` require root on Kali** — passwordless sudo
   is configured for these specific binaries only. Don't add new attack tools
   without updating `/etc/sudoers` on Kali.

10. **Ubuntu nginx is now running** — port 80 will accept connections. Future
    "port scan" attacks will see port 80 as OPEN (not closed), which produces
    different responses than scanning closed ports. Worth testing if attack
    fingerprints shift.

---

## 12. How to use this document in a new chat

Start the new chat with something like:

> Hi Claude, I'm continuing work on an AI/ML firewall project. Below is the full
> context document from my last session. Please read it carefully, then I'll tell
> you what I want to work on next. Don't start writing code until I confirm.
>
> [paste contents of PROJECT_CONTEXT.md]

Then in your second message, tell the new Claude exactly what you want to do next.
If the work involves code, also paste the current contents of any relevant scripts
and a few sample rows from `flows_labeled.csv`.

---

*Last updated: end of Phase 2D. Phase 3 paused at user's request.*
*Update this file at the end of each phase or major milestone.*
