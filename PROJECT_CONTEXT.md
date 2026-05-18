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

**Internal IP `192.168.56.100`:** appears in flows as single-packet UDP-576
broadcasts. Likely Windows NetBIOS/mDNS background chatter. Labeled `benign_idle`
when it shows up in review queues.

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
│   ├── models/
│   │   ├── rf_baseline.pkl         # Current production RF
│   │   ├── rf_baseline.json        # RF metadata + metrics
│   │   ├── iforest_baseline.pkl    # Current production IF
│   │   ├── iforest_baseline.json   # IF metadata + metrics
│   │   ├── rf_v1.pkl               # Archived old version (created on --commit)
│   │   └── iforest_v1.pkl          # Archived old version
│   ├── agent/                      # Created by run_agent on first run
│   │   ├── decisions.jsonl         # Full audit log of every decision
│   │   ├── watch.jsonl             # WATCH-only subset for easy review
│   │   └── unblocks.jsonl          # Audit of every kill-switch action
│   └── review/                     # Phase 5 working area
│       ├── review_queue.csv        # Volatile workspace for current labeling session
│       ├── review_queue.meta.json  # Stats about the current queue
│       ├── review_queue.backup_*.csv  # Auto-backups before each labeling session
│       └── flows_reviewed.csv      # CUMULATIVE archive of all finalized labels
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
│   ├── test_live_tailer.py         # Phase 4C — smoke test the real-time log tailer
│   ├── test_block_executor.py      # Phase 4D — validate the block executor
│   ├── run_agent.py                # Phase 4E — main live agent
│   ├── unblock_all.py              # Phase 4F — kill switch / unblock utility
│   ├── build_review_queue.py       # Phase 5A.1 — build review queue (skips finalized)
│   ├── review_queue.py             # Phase 5B — interactive CLI review tool
│   ├── finalize_reviews.py         # Phase 5B.5 — move labels into cumulative archive
│   └── retrain.py                  # Phase 5C/5D — retrain with strict gate + commit
├── src/
│   ├── __init__.py
│   ├── fw_parser.py                # Parse FW_LOG lines (ISO 8601 + legacy formats)
│   ├── flow_features.py            # Aggregate packets into flows; manifest labeling
│   ├── attack_orchestrator.py      # AttackOrchestrator with server-clock timing
│   ├── ssh_client.py               # ssh_connection() + kali_connection() managers
│   ├── model_io.py                 # Model save/load with feature schema check
│   ├── decision_engine.py          # Phase 4B — Decision dataclass + DecisionEngine
│   ├── block_executor.py           # Phase 4D — safety-wrapped ipset blocker (5A.0: logs full flow)
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
- `scripts/run_cycle.py` — Phase 5E, orchestration wrapper for 5A→5B→5B.5→5C
- Reporting/dashboard layer — Phase 6 (likely Streamlit)

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

(See previous version of this document; unchanged.)

### ✅ Phase 3 — Model training and evaluation

172 flows total, 33 malicious / 139 benign. 80/20 split with `random_state=42`
(important — Phase 5C reuses this seed to recreate the same test set).

**RF baseline:** P=0.75, R=0.857, F1=0.80 (malicious)
**IF baseline:** F1=0.639 (malicious), ROC-AUC=0.863

### ✅ Phase 4A — Blocking infrastructure
### ✅ Phase 4B — Decision engine
### ✅ Phase 4C — Live tailer
### ✅ Phase 4D — Block executor (Phase 5A.0 update: also logs full flow features to JSONL)
### ✅ Phase 4E — Live agent (`run_agent.py`)

End-to-end validated. SYN scan detection works at `--rf-threshold 0.80`:
RF=0.83, IF=anomalous → DRY_RUN_BLOCK. Allowlist correctly protects operator IP.

### ✅ Phase 4F — Kill switch (`unblock_all.py`)

Three modes: `--list`, `--ip <addr>`, full flush. Audit log at `data/agent/unblocks.jsonl`.

### ✅ Phase 5A.0 — Block executor patched to log full feature vector

`handle()` accepts optional `flow=` parameter; when provided, the full 19-feature
dict is written to `decisions.jsonl` under a `"flow"` key. Backward compatible
with old test code that doesn't pass it.

### ✅ Phase 5A.1 — Review queue builder (`build_review_queue.py`)

Reads `decisions.jsonl`, samples ALLOWs (5% with near-miss boost), keeps all
BLOCKs and WATCHes, groups consecutive same-IP BLOCKs as incidents, writes
`data/review/review_queue.csv`. **Skips already-finalized rows** (matches on
`(src_ip, window_start)` against `flows_reviewed.csv`) so subsequent rebuilds
only show new work.

### ✅ Phase 5B — Interactive review CLI (`review_queue.py`)

Walks user through each row, prompts `[a]ttack / [b]enign / [s]kip / [u]nsure`,
with attack-type and benign-type submenus. Auto-saves after every label,
timestamped backup at session start, resumable.

### ✅ Phase 5B.5 — Finalize reviews (`finalize_reviews.py`)

Moves rows with `needs_review=done` and binary `reviewed_label` from
`review_queue.csv` into the cumulative `flows_reviewed.csv` archive.
Deduplicates by `(src_ip, window_start)` keeping the latest label,
so re-labeling a row and re-finalizing corrects mistakes.

### ✅ Phase 5C — Retraining pipeline (`retrain.py`)

Combines `flows_labeled.csv` (137 train rows from the original split) with
`flows_reviewed.csv` (currently 25 reviewed rows), trains new RF + IF with
identical hyperparameters, evaluates BOTH old and new models on the SAME
35-row frozen test set, applies strict gate.

**Strict gate policy:** new wins iff Δprecision ≥ 0 AND Δrecall ≥ 0 on the
malicious class, for BOTH models. One regression fails all. `--commit` does
the swap; default is dry-run.

### ✅ Phase 5D — Versioning & rollback

Baked into `retrain.py --commit`. On commit, archives existing baseline as
`rf_v1.pkl` / `iforest_v1.pkl` (auto-incremented), then overwrites baseline
with new model. Rollback is `cp data/models/rf_v1.pkl data/models/rf_baseline.pkl`.

### 📌 Phase 5C empirical finding (worth documenting in dissertation)

First two retraining attempts (12 reviewed rows, then 25) were both **rejected**
by the strict gate. The malicious-precision metric on the 35-row frozen test
set regressed by 0.0833 in both cases (one extra false positive in 9 predicted
malicious flows). Adding more reviewed data did NOT change the numbers.

Root cause is probably test-set granularity: with only 7 malicious examples
in the held-out test set, precision quantizes in chunks of ~0.11, so the
strict gate is too sensitive to single-example flips. This is the gate doing
its job (refusing marginal improvements) but suggests that for production use,
either a larger held-out test set or a less brittle metric would be needed.

The **system is working as designed**; this is a methodological finding, not
a bug. SSH brute force WAS confirmed as a false negative (RF=0.38 in first run,
RF=0.51 in second — model has learned the signature is suspicious but not
crossed the threshold).

---

## 6. Key technical decisions made (and why)

(Unchanged from previous version, plus:)

12. **Volatile queue vs cumulative archive (Phase 5).** `review_queue.csv` is
    rebuilt fresh on every `build_review_queue` run. `flows_reviewed.csv` is
    the append-only archive of all labels ever applied. `retrain.py` reads
    from the archive, not the queue. This separation means rebuilds never
    destroy labeling work, and retraining always sees the complete label set.

13. **Strict gate, even when it fails.** With small test sets the gate may
    reject improvements indistinguishable from noise. We did not relax the
    gate when it rejected — that would defeat the purpose. Documented as a
    finding instead. Gate logic: per-model, malicious-class Δprecision ≥ 0
    AND Δrecall ≥ 0, with both models required to pass for swap to proceed.

14. **`random_state=42` reused EVERYWHERE.** The retrain pipeline depends on
    being able to recreate the EXACT original 80/20 test set from
    `flows_labeled.csv`. Both `train_ai.py` and `retrain.py` pass
    `random_state=42, test_size=0.2, stratify=y` to `train_test_split`,
    which deterministically reproduces the same partition.

---

## 7. What's next — Phase 5E plan (immediate next step)

**Goal:** Build `scripts/run_cycle.py` — orchestration wrapper that runs
the full retraining cycle with one command.

**Steps it would run:**
1. `build_review_queue` (rebuild queue from latest decisions.jsonl)
2. Prompt the user: "N rows to review — start now? [y/n]"
3. If yes: run `review_queue --skip-allowlist` interactively
4. `finalize_reviews` (move labels into archive)
5. `retrain` (dry-run by default)
6. Prompt the user: "Verdict was ACCEPT/REJECT. Commit? [y/n]"
7. If accepted and confirmed: `retrain --commit`

It's a UX wrapper. Each step already works individually. Estimated 1 hour.

---

## 8. Phase 6+ roadmap (future)

- **Phase 5E** — Orchestration wrapper (see above)
- **Phase 5.5 — Real armed-mode validation** — never tested `run_agent --arm`
  in real operation. Need a careful test plan: start agent armed, trigger one
  SYN scan, verify Kali actually gets blocked in ipset, verify allowlist still
  protects operator IP, manually unblock via kill switch, repeat.
- **Phase 6 — Reporting dashboard** (Streamlit): attacks over time, top attacker
  IPs, attack-type breakdown, confidence distribution, FP review queue browser.
- **Phase 7 (optional, advanced)** — post-compromise detection: simulating
  successful attacks and detecting lateral movement / exfiltration patterns.
- **Documentation pass** — update README, write up Phase 5 finding properly
  for dissertation results section.

---

## 9. Networking & ML concepts the user has been taught

(Unchanged. See previous version. New additions:)

- Continuous learning vs online learning (we chose periodic batch with HITL,
  not online — online is vulnerable to poisoning)
- Train/eval split reproducibility via `random_state`
- Strict gates vs loose gates in model deployment
- Test-set granularity effects (small test set = quantized metrics)
- Difference between volatile workspace and immutable archive in data pipelines

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
- **User asked for clear "Commands to run" sections at the END of each response**
  — separate from explanation/discussion. Never bury commands inside narrative.
- User has a separate dissertation paper task — IEEE 2-column LaTeX format.
  First draft delivered with intentional methodology-focused framing, results
  section reserved for May 31 (when models are trained — now done).
  User's professor verbally allowed AI assistance despite written "no AI" rule.

---

## 11. Things to watch out for

(Unchanged items omitted; new and updated:)

1. **Markdown autolink leakage** in pasted code — warn about these.

12. **Pasting commands at interactive prompts.** User has pasted bash commands
    into `review_queue.py`'s `[a]/[b]/[s]/...` prompt by accident. The tool
    correctly refuses and re-prompts. Warn the user that verification commands
    are for AFTER labeling, not during.

13. **Empty file from copy-paste mishap.** When asking the user to save a
    long file, the file may end up at 0 bytes if PyCharm autosaves before
    paste completes. If a script "does nothing" silently, first check
    `dir <file>` to confirm Length is non-zero.

14. **flows_reviewed.csv must have `window_start` filled in.** The skip-
    finalized logic in `build_review_queue.py` matches on
    `(src_ip, window_start)`. If a row has empty window_start, dedup fails
    silently and the user re-reviews finalized rows. `finalize_reviews.py`
    inherits whatever was in `review_queue.csv`, and `build_review_queue.py`
    always populates window_start, so this should be safe in normal flow.

15. **Strict gate rejections are normal.** Don't relax the gate or force-commit
    when it rejects. Either gather more data and retry, accept the rejection,
    or document the finding. The gate working is the gate doing its job.

---

## 12. How to use this document in a new chat

Start the new chat with something like:

> Hi Claude, I'm continuing work on an AI/ML firewall project. Below is the full
> context document from my last session. Please read it carefully, then I'll tell
> you what I want to work on next. Don't start writing code until I confirm.
>
> [paste contents of PROJECT_CONTEXT.md]

Then in your second message, tell the new Claude what to do next.
For Phase 5E: "We just finished Phase 5C/5D. Ready to start Phase 5E — the
orchestration wrapper."

---

*Last updated: end of Phase 5C/5D, including Phase 5C empirical finding.*
*Phase 5E (orchestration wrapper) is the immediate next step. After that:*
*real armed-mode validation, then Phase 6 dashboard.*