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
3. Automatically blocks attackers via `iptables` + `ipset` (time-bounded blocks)
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
| Server | Ubuntu 24.04 | `192.168.56.102` | iptables LOG sensor + ipset blocker + nginx on port 80 |
| Attacker | Kali Linux | `192.168.56.103` | Generates malicious traffic via SSH-driven orchestration |
| Operator | Windows + PyCharm | `192.168.56.1` (host-only adapter) | Runs Python scripts, generates benign traffic, owns the agent |

Credentials for both VMs are in `.env` (gitignored). See `.env.example` in repo
for the variable structure.

**VirtualBox dual NIC on Ubuntu (important quirk):**
- `enp0s3` (NAT, IP `10.0.2.15`) — outbound internet, brings real-world noise
- `enp0s8` (Host-Only, IP `192.168.56.102`) — VM-to-VM lab traffic

The firewall logs BOTH interfaces, so logs include real internet noise (Canonical
update servers, AWS, CDNs) mixed with lab traffic. Useful as benign baseline noise.

**Localhost noise:** `127.0.0.1` traffic appears because nginx and other local
services chatter on loopback. The decision engine's allowlist excludes 127.0.0.1,
the operator IP, and the NAT gateway from ever being blocked.

---

## 3. Current project structure

```
AI_IDS_Project/
├── .venv/                          # Python virtual environment (gitignored)
├── data/                           # All gitignored
│   ├── flows.csv                   # Raw flow output of collect_data
│   ├── flows_labeled.csv           # Flows with manifest-based labels (172 rows)
│   ├── attack_manifest.json        # Ground-truth attack timestamps
│   ├── benign_manifest.json        # Ground-truth benign-active session timestamps
│   └── models/
│       ├── rf_baseline.pkl         # Trained RandomForest classifier
│       ├── rf_baseline.json        # RF metadata + metrics
│       ├── iforest_baseline.pkl    # Trained IsolationForest anomaly detector
│       └── iforest_baseline.json   # IF metadata + metrics
├── scripts/
│   ├── __init__.py
│   ├── collect_data.py             # Batch: SSH to server, parse logs, build flows
│   ├── simulate_attacks.py         # Phase 2C — orchestrate attack suite via Kali SSH
│   ├── generate_benign.py          # Phase 2D — generate benign traffic from operator
│   ├── relabel_with_manifest.py    # Label flows.csv from both manifests
│   ├── test_connections.py         # SSH smoke test for both VMs
│   ├── train_ai.py                 # Phase 3B — train RandomForest classifier
│   ├── train_anomaly.py            # Phase 3C — train IsolationForest
│   ├── test_decision_engine.py     # Phase 4B — validate decision logic on flows.csv
│   └── test_live_tailer.py         # Phase 4C — smoke test the real-time log tailer
├── src/
│   ├── __init__.py
│   ├── fw_parser.py                # Parse FW_LOG lines (ISO 8601 + legacy formats)
│   ├── flow_features.py            # Aggregate packets into flows; manifest labeling
│   ├── attack_orchestrator.py      # AttackOrchestrator with server-clock timing
│   ├── ssh_client.py               # ssh_connection() + kali_connection() managers
│   ├── model_io.py                 # Model save/load with feature schema check
│   ├── decision_engine.py          # Phase 4B — Decision dataclass + DecisionEngine
│   └── live_tailer.py              # Phase 4C — live SSH tail + flow rolling
├── .env                            # SECRETS — gitignored
├── .env.example                    # Sanitized template (in repo)
├── .gitignore
├── LICENSE                         # MIT
├── PROJECT_CONTEXT.md              # this file
├── README.md                       # Public-facing project description
└── requirements.txt                # paramiko, pandas, scikit-learn, joblib, python-dotenv, numpy
```

**Files NOT yet created (planned):**
- `src/block_executor.py` — Phase 4D, the safety-wrapped ipset block applier
- `scripts/run_agent.py` — Phase 4E, the main live agent wiring everything together
- `scripts/unblock_all.py` — Phase 4F, kill-switch utility
- Reporting/dashboard layer — Phase 6

---

## 4. Server-side configuration (already done)

**iptables on Ubuntu, persisted via netfilter-persistent:**
```
Chain INPUT (policy ACCEPT)
1    DROP   match-set ml_blocks src
2    LOG    prefix "FW_LOG: "
```

The DROP rule references the `ml_blocks` ipset (created with `timeout 3600`,
so blocks auto-expire after 1 hour). One iptables rule, one ipset entry per
blocked IP, O(1) blocking.

**Setup commands (already executed, don't re-run unless rebuilding):**
```bash
sudo ipset create ml_blocks hash:ip timeout 3600
sudo iptables -I INPUT 1 -m set --match-set ml_blocks src -j DROP
sudo iptables -A INPUT -j LOG --log-prefix "FW_LOG: "
sudo netfilter-persistent save
```

**Passwordless sudo on Ubuntu (`/etc/sudoers`):**
```
admin-ai ALL=(ALL) NOPASSWD: /usr/bin/grep, /bin/grep, /usr/sbin/iptables, /usr/sbin/ipset, /usr/sbin/tail, /bin/tail
```

**Passwordless sudo on Kali:**
```
attacker ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/hping3, /usr/bin/hydra, /usr/bin/timeout
```

**Kali tools installed:** nmap, hping3, hydra, paramiko (Python).

**Kali helper script:** `~/attack_tools/ssh_bruteforce.py` — paramiko-based brute
force simulator used by `simulate_attacks.py`.

**Ubuntu services running:** sshd, nginx (with `/var/www/html/test.json` test endpoint).

**Log location:** `/var/log/kern.log` — uses ISO 8601 timestamps.

---

## 5. What's been completed

### ✅ Phase 1 — Flow-based feature extraction

Replaced per-packet ML (effectively hard-coded rules) with per-flow ML using
behavioral features aggregated over 60-second windows.

**~20 features per `(src_ip, time_window)` flow:**
- **Volume:** n_packets, packets_per_sec, total_bytes, avg_packet_size, std_packet_size
- **Diversity:** unique_dst_ports, unique_src_ports, unique_protocols, unique_dst_ips
- **TCP flags:** syn_ratio, syn_only_ratio (★), ack_ratio, fin_ratio, rst_ratio
- **Protocol mix:** tcp_ratio, udp_ratio, icmp_ratio
- **Targeting:** common_port_ratio, dst_port_std

### ✅ Phase 2 — Ground-truth data generation

**2A/B:** SSH connectivity to both VMs + AttackOrchestrator with server-clock timing.
Manifest schema:
```json
{"attack_type": "...", "attacker_ip": "...", "target_ip": "...",
 "start_ts": "ISO8601", "end_ts": "ISO8601", "command": "...", "notes": "..."}
```

**2C — 6 attack types** (each stresses different features):
- `syn_scan` (nmap -sS, 1-1024) — port diversity + syn_only_ratio
- `fin_scan` (nmap -sF, 1-1024) — fin_ratio
- `udp_scan` (nmap -sU, top 50) — udp_ratio
- `slow_scan` (nmap -sS -T1, 5 ports) — port diversity at low rate
- `syn_flood` (hping3 --flood -S, 5s) — raw packet rate
- `ssh_brute` (paramiko, 50 wrong pw) — single-port high-rate auth attempts

**Cooldowns: 90 seconds** between attacks (30s caused window collisions).

**2D — 6 benign-active traffic types** from operator host:
- `ssh_session`, `http_get`, `ping_burst`, `file_xfer`, `dns_query`, `mixed`

Same 90s cooldowns. Same `get_server_time()` for clock consistency.

**Three-tier labeling** in `label_flows_from_manifest()`:
- `label=1, attack_type=<type>` — matches attack manifest
- `label=0, attack_type='benign_active', traffic_type=<type>` — matches benign manifest
- `label=0, attack_type='benign_idle'` — uncontrolled background

Multi-overlap windows: greatest-temporal-overlap wins. `all_attack_types` and
`all_traffic_types` columns retain full list for debugging.

### ✅ Phase 3 — Model training and evaluation

**Current dataset:** 172 flows total. After 3 full attack+benign cycles:
- 33 malicious (across all 6 attack types)
- 21 benign-active (across all 6 traffic types)
- 118 benign-idle (background noise)

**3B — RandomForest classifier (`rf_baseline`):**
- 80/20 stratified split, class_weight='balanced', n_estimators=200, max_depth=10
- **Test results:**
  - Benign: precision=0.963, recall=0.929, F1=0.945
  - Malicious: precision=0.750, recall=0.857, **F1=0.800**
- Top features: avg_packet_size, n_packets, syn_ratio, total_bytes, unique_src_ports
- Schema-versioned via `src/model_io.py`

**3C — IsolationForest anomaly detector (`iforest_baseline`):**
- Trained on benign flows only (139 rows), n_estimators=300, contamination='auto'
- **Test results:**
  - Malicious: precision=0.590, recall=0.697, F1=0.639
  - **ROC-AUC=0.863**
- Threshold sweep recorded for Phase 4 calibration (80th percentile sweet spot)
- Catches attacks the supervised model never saw — complementary

### ✅ Phase 4A — Blocking infrastructure

ipset + iptables setup on Ubuntu (see Section 4). Persisted via netfilter-persistent.
Smoke-tested: add/remove IPs from `ml_blocks` works, timeout decrements correctly.

### ✅ Phase 4B — Decision engine (`src/decision_engine.py`)

Pure Python, no side effects. Takes a flow dict, returns a structured `Decision`.

**Six-layer safety design:**
1. Hardcoded allowlist (operator IP, 127.0.0.1, NAT gateway) — checked BEFORE models
2. RF confidence threshold (default 0.85)
3. Conservative combining policy
4. Time-limited blocks (1h via ipset timeout) — Phase 4A
5. Rate limit (planned in 4D)
6. DRY-RUN mode (planned in 4E)

**Verdict policy:**
- `ALLOW` — RF benign AND IF normal
- `WATCH` — one model fires but not both at high confidence (logged, no firewall action)
- `BLOCK` — RF malicious with prob ≥ threshold AND IF anomalous

**Decision object** carries: verdict, RF prob, IF score, allowlist flag, human-readable
reason, top contributing features (for audit log explainability).

**Validation on 172 historical flows:**
- 131 ALLOW, 32 WATCH, 9 BLOCK
- True positive blocks: 8/33 malicious
- False positive blocks: 1/139 benign (a Canonical/AWS-style high-throughput flow)
- 80 operator IP flows: 100% ALLOW (allowlist verified)

### ✅ Phase 4C — Live tailer (`src/live_tailer.py`)

Real-time SSH log streaming. Converts packet stream → flow stream with no side effects.

**Mechanism:**
- `sudo tail -F -n 0 /var/log/kern.log` over SSH (only new packets, not history)
- Per-IP buffer of packets keyed by 60s window
- Watermark = most recent packet timestamp (uses server clock, not local)
- Window closes when watermark > window_start + 60s + 10s grace
- Closed window → compute features via `_compute_flow_features` (same code as batch)
- Emit flow via callback; consumer decides what to do with it

**Reliability:**
- SSH disconnect → exponential backoff reconnect, state preserved
- Parse errors → silently skip (one bad line doesn't kill the agent)
- Callback errors → logged, agent continues
- Ctrl-C → graceful stop via threading.Event

**Smoke-test results (real run):**
- 8,409 packets parsed
- 0 packets dropped
- 10 flows emitted across multiple source IPs
- 0 SSH reconnects (stable)
- Detected nmap -sS attack from Kali in real time: `syn_only=0.98, ports=100, tcp=1.00`

---

## 6. Key technical decisions made (and why)

1. **Flows over packets** — per-packet ML degenerates into hardcoded port rules.
2. **60-second windows** — balance between temporal resolution and statistical sample size.
3. **Manifest-based labeling, not heuristic** — ground truth from "we ran this attack
   at this time" avoids the circularity of heuristic-then-train-on-heuristic.
4. **Three-tier labels** — separating benign-active from benign-idle exposes the
   "blocks legitimate users" failure mode that binary metrics hide.
5. **Periodic retraining, NOT online learning** — online is vulnerable to poisoning.
6. **`.env` for credentials, gitignored** — repo is public.
7. **`ipset` with timeouts, not raw iptables** — O(1) blocking, auto-expiry,
   protects against permanent false positives.
8. **Server-clock timestamps in manifests AND live watermark** — kern.log is in
   server time; using local time would misalign labels.
9. **Two models (supervised RF + unsupervised IF)** — RF for known attacks,
   IF for novelty. Conservative combining: block only when both agree.
10. **Allowlist checked BEFORE model inference** — defense in depth. Even if models
    catastrophically misbehave, allowlisted IPs are mathematically un-blockable.
11. **Live tailer reads but doesn't act** — strict separation of concerns. Phase 4D
    adds the executor; this module remains side-effect-free.

---

## 7. What's next — Phase 4D plan (immediate next step)

**Goal:** Build `src/block_executor.py` — the careful module that actually touches
the firewall. Most safety-critical component in the system.

**Components:**

1. `BlockExecutor` class that takes a `Decision` and applies action accordingly:
   - `ALLOW` → log to decisions log, do nothing
   - `WATCH` → log to a separate watch log for review
   - `BLOCK` → double-check allowlist (paranoid, don't trust upstream),
     check rate limit, SSH to Ubuntu, `sudo ipset add ml_blocks <ip>`, log decision
2. **DRY-RUN mode** as default — every BLOCK is logged with `[DRY-RUN]` prefix
   but no ipset action occurs. Only flips to real mode when explicitly enabled.
3. **Rate limit** — max N blocks per minute (default 5). Prevents runaway blocking.
4. **Decision log** — JSONL file at `data/agent/decisions.jsonl`, one line per decision,
   full audit trail.
5. **Already-blocked tracking** — don't re-issue ipset add for IPs that are still
   timing out (idempotent).

After 4D, **Phase 4E** wires LiveTailer + DecisionEngine + BlockExecutor into a
single runnable `scripts/run_agent.py`. Test thoroughly in DRY-RUN before enabling
real blocking.

**Phase 4F** is the kill switch — `scripts/unblock_all.py` to instantly flush
`ml_blocks` if anything goes wrong.

---

## 8. Phase 5+ roadmap (future)

- **Phase 5 — Continuous learning pipeline** with periodic batch retraining and
  human-in-the-loop label confirmation. Reads decisions.jsonl + new manifests,
  retrains, archives old model versions.
- **Phase 6 — Reporting dashboard** (Streamlit or Flask): attacks over time,
  top attacker IPs, attack-type breakdown, confidence distribution, FP review queue.
- **Phase 7 (optional, advanced)** — post-compromise detection: simulating
  successful attacks and detecting lateral movement / exfiltration patterns.

---

## 9. Networking concepts the user has been taught

(Don't re-explain unprompted; reference if needed)

- OSI/TCP-IP layer model basics
- Public vs private IP ranges, NAT mechanics
- Why VirtualBox VMs have two IPs (NAT + Host-Only)
- TCP vs UDP differences; TCP three-way handshake
- TCP flags: SYN, ACK, FIN, RST, PSH, URG
- Why SYN scans are detectable (`syn_only_ratio = 1.0`)
- Variant scan types (FIN, NULL, XMAS, ACK)
- Common ports cheat sheet
- iptables chains (INPUT/OUTPUT/FORWARD), targets (ACCEPT/DROP/REJECT/LOG)
- Stateful vs stateless firewalls
- ipset semantics (Phase 4A) — hash:ip with timeouts, single iptables rule references the set
- Brute force, SYN flood, Slowloris, MITM, ARP spoofing concepts

**ML concepts the user has been taught:**
- Train/test split, why it matters
- Why accuracy is misleading on imbalanced data
- Precision, recall, F1, confusion matrix
- Stratified split (preserving class proportions)
- class_weight='balanced'
- Random Forest intuition (many trees, majority vote)
- Feature importance (and its limits — global, not per-prediction)
- Isolation Forest intuition (anomalies are easy to isolate)
- ROC curve and AUC (threshold-independent quality metric)
- Threshold sweep / operating point selection
- Contamination parameter and why its default of 0.01 was wrong for our data

---

## 10. Communication style preferences

- Explain WHY before code — user values understanding the design
- Step-by-step instructions with explicit file paths and exact commands
- Honest pushback when designs have flaws (user invited this)
- Long detailed responses welcomed when educational
- User catches markdown autolink artifacts (`[parser.py](http://parser.py)`) — warn about these
- User runs everything in PyCharm on Windows; commands should be PowerShell-friendly
- **User explicitly asked to be notified at phase boundaries** before moving forward.
  Honor explicit pause requests.
- User has a separate dissertation paper task — IEEE 2-column LaTeX format.
  First draft delivered with intentional methodology-focused framing, results
  section reserved for May 31 (when models are trained — now done).
  User's professor verbally allowed AI assistance despite written "no AI" rule.

---

## 11. Things to watch out for

1. **Markdown autolink leakage** in pasted code — warn about these.

2. **Empty DataFrame crashes** — original `collect_data.py` had a `KeyError: 'label'`
   bug. Hardened. Apply same defensive pattern in future scripts.

3. **kern.log timestamp format is ISO 8601** on this Ubuntu version. Parser handles
   both ISO and legacy syslog formats. Don't break this when refactoring.

4. **Background internet noise** dominates raw log volume. Most flows are this,
   not attacks. "High packet count" alone is NOT a strong attack signal.

5. **Old `ai_agent_live.py`** (deleted) had `break` after first detection — killed
   the agent permanently. Phase 4E rewrite must NOT do this. Block-and-continue.

6. **`iptables -A` vs `-I`** — append vs insert at top. Use `-I INPUT 1` for blocking
   rules to avoid being shadowed by earlier ACCEPT rules.

7. **Allowlist is sacred.** 127.0.0.1, operator IP (192.168.56.1), NAT gateway
   (10.0.2.x) MUST never be blocked. Allowlist check happens BEFORE model inference.

8. **Cooldowns between orchestrated sessions ≥90s** — shorter caused window collisions
   in Phase 2C.

9. **Hping3 floods and nmap SYN scans require root on Kali** — passwordless sudo
   configured for specific binaries only. Don't add new attack tools without
   updating `/etc/sudoers` on Kali.

10. **Duplicate LOG rules bug recurred twice** in this project. Root cause: running
    `iptables -A INPUT -j LOG ...` without first flushing or checking for existing
    rule. Phase 4E setup script should use idempotent pattern:
    ```bash
    sudo iptables -C INPUT -j LOG --log-prefix "FW_LOG: " 2>/dev/null || \
      sudo iptables -A INPUT -j LOG --log-prefix "FW_LOG: "
    ```
    Symptom: kern.log packet counts inflated 2x. Always verify with
    `sudo iptables -L INPUT -n -v --line-numbers` after firewall changes.

11. **VM reboot considerations:**
    - iptables rules: persisted via netfilter-persistent
    - ipset: persisted via ipset-persistent (but as empty set — entries don't survive)
    - sudoers: persisted (kernel-independent)
    - Kali SSH server: enabled, starts on boot
    After reboot, verify `sudo iptables -L INPUT -n` shows exactly DROP+LOG before
    running anything that depends on logging.

12. **PowerShell `curl` is actually `Invoke-WebRequest`** — heavier than expected.
    Use `curl.exe` for Unix-style curl, or `Invoke-WebRequest -UseBasicParsing`.

---

## 12. How to use this document in a new chat

Start the new chat with something like:

> Hi Claude, I'm continuing work on an AI/ML firewall project. Below is the full
> context document from my last session. Please read it carefully, then I'll tell
> you what I want to work on next. Don't start writing code until I confirm.
>
> [paste contents of PROJECT_CONTEXT.md]

Then in your second message, tell the new Claude what to do next.
For Phase 4D: "We just finished Phase 4C. Ready to start Phase 4D — the block executor."

If the work involves code, also paste current contents of any relevant scripts
and a few sample rows from `flows_labeled.csv` (or the model JSON metadata if
the task involves models).

---

*Last updated: end of Phase 4C. Phase 4D is the immediate next step.*
*Update this file at the end of each phase or major milestone.*
