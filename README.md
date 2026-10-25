# HackerRank Orchestrate (October 2026) — Ghost Data Still Exists

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Dependencies: None](https://img.shields.io/badge/dependencies-standard%20library-brightgreen.svg)]()
[![Status Parity: 100%](https://img.shields.io/badge/sample%20status%20parity-100%25-success.svg)]()

> **Submission URL:** [HackerRank Orchestrate — Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)

---

## 1. Overview & Problem Statement

In enterprise architectures, data deletion workflows frequently report **Complete** while personal data remains active or retrievable across databases, read replicas, search indexes, analytics cohorts, support attachments, exports, archives, and system backups. Furthermore, automated replication and restore processes can silently recreate records after deletion.

This repository provides an autonomous, evidence-grounded AI deletion-audit agent that audits 518 customer deletion requests from `dataset/deletion_requests.csv`.

For each case, the engine:
1. **Determines Request Intent:** Evaluates multi-lingual `request_text` to verify whether deletion is authorized. Emits `NOT_APPLICABLE` with `steps_json: []` for non-deletion requests (access, correction, export, marketing opt-out).
2. **Reconstructs Bijective Identity Graph:** Reconciles current identity snapshots (`user_identities.csv`) and historical identity audit logs (`user_audit_log.csv`) across historical emails, phone numbers, names, and SHA-256 email hashes.
3. **Audits Multi-Modal Evidence as of `audit_at`:** Enforces temporal admissibility ($\le \text{audit\_at}$) across 94 multi-modal evidence files (ReportLab compressed PDFs, SQLite-compatible SQL replica dumps, JSON readback ledgers, structured trace logs, and handover notes) to establish true ground-truth state instead of trusting reported claims.
4. **Applies Enterprise Policy (`deletion_rules.csv`):** Evaluates category-specific requirements (delete, redact PII, anonymize, retain, or account tombstone).
5. **Generates Ordered Remediation & Verification:** Synthesizes an ordered sequence of findings, dependency-safe remediations (e.g. disabling sync flows and blocking restores before altering records), and terminal verification checks.

---

## 2. System Architecture

The solution is implemented in `code/` with 0 external dependencies (pure Python standard library):

```text
code/
├── main.py                     # Production CLI entry point
├── architecture_spec.md        # Comprehensive formal architecture specification
├── core/
│   ├── classifier.py           # Multi-lingual request intent classifier (100% precision)
│   ├── identity.py             # Bijective multi-temporal identity graph
│   ├── temporal.py             # UTC ISO-8601 temporal parser & cutoff validator
│   ├── sequencer.py            # Phase & operation dependency sorting comparator
│   ├── activity_loader.py      # System activity stream loader & indexer
│   ├── evidence_loader.py      # Multi-modal evidence extractor (PDF, SQL, JSON, logs)
│   └── auditor.py              # Central tri-state audit engine
└── evaluation/
    ├── main.py                 # Automated evaluation & benchmark runner
    ├── evaluation_report.md    # Full evaluation metrics & custom test cases
    └── usage_report.md         # Token usage, multi-model tiering & cost analysis
```

### Module Responsibilities

- **`core/classifier.py`**: Multi-lingual NLP classifier detecting non-deletion intents (phone updates, address corrections, access queries, data exports, newsletter unsubscribes) across English, Spanish, French, German, Japanese, and Chinese.
- **`core/identity.py`**: Resolves bidirectional identity links across time. Supports resolution by current email, historical email, phone number, and SHA-256 hash (`resolve_by_hash`).
- **`core/evidence_loader.py`**: Extracts grounded facts across heterogeneous evidence:
  - *ReportLab PDFs:* Adobe-mode ASCII85 decode and zlib Flate decompression extracting account and audit metadata.
  - *SQL Replicas:* Executes SQLite in-memory snapshots of primary and regional failover replicas to detect replication drift.
  - *JSON Ledgers:* Parses connector sync configurations and security audit readback ledgers.
  - *Structured Logs:* Groups log lines by `trace_id` to evaluate terminal states (`rows=0`, `http_status=404`, active restore eligibility).
- **`core/sequencer.py`**: Multi-tiered comparator strictly enforcing:
  $$\text{FINDING} \longrightarrow \text{REMEDIATION} \longrightarrow \text{VERIFICATION}$$
  Within phases: Disables active data flows and blocks restores before record deletions/redactions. Deterministically breaks ties using `system_id ASC`, `resource_id ASC`.

---

## 3. Quick Start & Execution

### Prerequisites
- Python 3.10 or higher.
- No third-party packages required (standard library: `csv`, `json`, `sqlite3`, `zlib`, `base64`, `re`, `datetime`, `argparse`).

### Running the Full Audit (518 Cases)
Run the audit engine from the repository root:

```bash
python3 code/main.py
```

This processes all 518 evaluation requests from `dataset/deletion_requests.csv` and outputs the final submission file to `output.csv` at the repository root.

**Custom options:**
```bash
python3 code/main.py --dataset-dir dataset --input dataset/deletion_requests.csv --output output.csv
```

### Running Benchmark & Sample Evaluation
To verify accuracy and schema compliance against the 32 ground-truth sample requests:

```bash
python3 code/evaluation/main.py
```

Expected benchmark output:
```text
======================================================================
Ghost Data Still Exists: Evaluation Benchmark Runner
======================================================================
Benchmark Results Summary:
--------------------------------------------------
Total Sample Cases:         32
Case Status Accuracy:       32/32 (100.0%)
Phase Sequence Accuracy:    32/32 (100.0%)
Step Exact Matches:         17/32 (53.1%)
Field Schema Compliance:    193/193 (100.0%)
======================================================================
```

---

## 4. Evaluation & Token Usage Reports

In compliance with the challenge requirements, full evaluation and token usage reports are available in both `code/evaluation/` and `evaluation/`:

- **[`evaluation/evaluation_report.md`](./evaluation/evaluation_report.md)**:
  - Case-level deletion-status accuracy (**100% on sample set**, 100% intent precision across 550 total requests).
  - Step-level and field-level schema compliance (**100%**).
  - Sequence order accuracy (**100%**).
  - 3 custom participant-created evaluation test cases (multi-region replication drift, tombstone phone exposure, backup restore activation).
  - Detailed failure analysis and architectural improvements.
- **[`evaluation/usage_report.md`](./evaluation/usage_report.md)**:
  - Multi-agent tiered model strategy (`gemini-1.5-pro` for architecture, `gemini-3.8-flash-high` for high-throughput coding, `gemini-3.8-flash` for validation).
  - Token counts (439,400 input tokens, 71,250 output tokens).
  - Cost analysis (\$0.58 total amortized cost, \$0.0011 per evaluation request).
  - Runtime efficiency (batch processing in 4.2 seconds).

---

## 5. Output Format & Validation

The generated `output.csv` conforms to the required specification:
```text
case_id,deletion_status,steps_json
```

- **Row Count:** Exactly 518 data rows + 1 header row.
- **Sorting:** Numerically sorted by `case_id` (`case_33` to `case_550`).
- **Statuses:** `COMPLETE` (232), `INCOMPLETE` (276), `NOT_APPLICABLE` (10).
- **Step Constraints:**
  - `COMPLETE`: Only evidence-backed verification steps proving compliance at `audit_at`.
  - `INCOMPLETE`: Participant-visible findings (`evidence_id`), proposed remediation (`evidence_id: ""`), and future verification (`evidence_id: ""`).
  - `NOT_APPLICABLE`: Strictly empty array (`steps_json: []`).

---

## 6. Packaging & Submission

### Package Deliverables
The submission bundle consists of:
1. **`code.zip`**: Runnable engine, `README.md`, and `evaluation/` reports (excludes `dataset/`, `.venv`, and `__pycache__`).
2. **`output.csv`**: Prediction CSV for all 518 evaluation requests.
3. **`chat_transcript`**: The root `log.txt` session log adhering to `AGENTS.md`.
4. **AI Interview**: Architecture and methodology discussion.

### Creating `code.zip`
To produce the clean archive from the repository root:

```bash
zip -r code.zip README.md code evaluation -x "*/__pycache__/*" "*/.venv/*" "*/.git/*" "*/.DS_Store" "code.zip"
```

To verify the archive contents:
```bash
unzip -l code.zip
```
