# Formal Architecture Specification: Ghost Data Still Exists

**Author / Role:** Logic & Architecture Specialist (Pro Tier Reasoning Subagent)  
**Target Repository:** `hackerrank-orchestrate-october26`  
**Document Version:** 1.0.0 (Release-Ready Blueprint for Phase 2 Implementation)  
**Date:** October 2026  

---

## 1. Executive Summary & Problem Formulation

In the Northstar Shop commerce ecosystem, customer deletion requests frequently report a false status of `COMPLETE`. Downstream systems—including database replicas, search clusters, analytics pipelines, support document stores, active API integrations, and backup archives—often continue to store direct Personal Identifiable Information (PII) or maintain active synchronization flows that can resurrect deleted entities ("ghost data").

The audit agent must evaluate 518 evaluation cases (`dataset/deletion_requests.csv`) and 32 sample validation cases (`dataset/sample_deletion_requests.csv`), establishing the ground truth strictly as of each request's `audit_at` cutoff timestamp.

### 1.1 The Tri-State Decision Space

For every request $C$, the system determines a discrete status:
$$\text{Status}(C) \in \{\text{COMPLETE}, \text{INCOMPLETE}, \text{NOT_APPLICABLE}\}$$

1. **`NOT_APPLICABLE`**: The request text does not authorize personal data deletion (e.g., access, rectification, portability/export, marketing opt-out, or credential reset). Output format is strictly:
   ```json
   []
   ```
2. **`INCOMPLETE`**: The request authorizes deletion, but as of `audit_at`, one or more policy violations exist (remaining unredacted records, exposed direct PII, active sync connectors, or unblocked restore points). The output contains:
   - Phase 1: `FINDING` steps citing participant-visible evidence.
   - Phase 2: `REMEDIATION` steps detailing corrective actions (`evidence_id: ""`).
   - Phase 3: `VERIFICATION` steps defining post-remediation validation checks (`evidence_id: ""`).
3. **`COMPLETE`**: The request authorizes deletion, and as of `audit_at`, all required deletions, redactions, anonymizations, flow disablings, and restore blocks have been verified, while mandatory audit/hold records remain preserved. The output contains:
   - Phase 3: `VERIFICATION` steps only, each citing the exact participant-visible `evidence_id` that validates compliance.

---

## 2. Intent Classification Engine

### 2.1 Domain Decision Criteria

A deletion request is valid only if the subject explicitly requests permanent account closure or data erasure. Under GDPR/CCPA, subjects frequently submit other distinct requests that must **not** be treated as account deletions.

The classifier operates as a deterministic decision tree:

```
                      [Request Text Input]
                                |
             +------------------+------------------+
             |                                     |
   Contains Explicit Negation?              No Negation Found
   ("keep the account",                     Check Multi-lingual
    "leave account active",                 Erasure Keywords
    "without removing records",             ("delete", "erase",
    "not asking for deletion",               "close", "supprimer",
    "continue using service")                "eliminar", "削除", "삭제")
             |                                     |
             v                                     v
      NOT_APPLICABLE                        Is Intent Erasure?
       (steps_json = [])                    +------+------+
                                            |             |
                                          YES             NO (Access/Export)
                                            |             |
                                            v             v
                                         DELETION   NOT_APPLICABLE
```

### 2.2 Intent Categories and Exact Lexical Rules

1. **Category `EDIT` / `CORRECTION` (GDPR Art. 16 Rectification):**
   - *Indicators:* Misspelled name, updating phone number, changing email address, updating profile details.
   - *Boundary Condition:* Explicit directives to leave account active (e.g., *"The mobile number on my profile is out of date. Please replace it with the new one and leave the account active."* or *"My surname is misspelled on the account. Can you correct it without removing any of my records?"*).
   - *Verdict:* `NOT_APPLICABLE`.

2. **Category `OPT_OUT` (Marketing / Communication Preferences):**
   - *Indicators:* Unsubscribing from promotional emails, removing from marketing lists, keeping transactional receipts.
   - *Boundary Condition:* Explicit retention request (e.g., *"Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion."* or *"Please remove me from marketing lists only. I still want receipts and service messages for this account."*).
   - *Verdict:* `NOT_APPLICABLE`.

3. **Category `EXPORT` / `PORTABILITY` (GDPR Art. 20 Data Portability):**
   - *Indicators:* Download account information, portable format, copy of invoices, copy of purchase history.
   - *Boundary Condition:* Directives preserving existing account (e.g., *"I'd like to download my account information in a portable format. Please keep the account as it is."* or *"I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."*).
   - *Verdict:* `NOT_APPLICABLE`.

4. **Category `ACCESS` / `INQUIRY` (GDPR Art. 15 Subject Access):**
   - *Indicators:* Inquiries about data held, login reset assistance, account recovery without closure.
   - *Boundary Condition:* Explicit non-erasure declaration (e.g., *"Can you tell me what personal information you hold about me? This is an information request, not a request to erase it."* or *"I can't access my profile and need help resetting the login. Do not close the account."*).
   - *Verdict:* `NOT_APPLICABLE`.

5. **Category `DELETION` (GDPR Art. 17 Right to Erasure):**
   - *English Keywords:* `delete`, `deletion`, `erase`, `erased`, `erasure`, `close`, `remove`, `permanently remove`, `wipe`.
   - *French Keywords:* `suppression`, `supprimer`, `effacer`, `fermer`.
   - *Spanish / Portuguese Keywords:* `eliminar`, `eliminación`, `exclusão`, `excluir`, `borrar`, `cancelar conta`.
   - *German Keywords:* `löschen`, `löschung`, `entfernen`.
   - *Japanese Keywords:* `削除`, `消去`, `アカウントの削除`.
   - *Korean Keywords:* `삭제`, `계정 삭제`, `영구 삭제`.
   - *Verdict:* `DELETION` (Proceed to Identity Resolution and Audit).

---

## 3. Bijective Identity Resolution Graph

### 3.1 Formal Definition

A user $u$ is defined as a tuple:
$$u = \langle \text{user\_id}, \mathcal{N}_u, \mathcal{E}_u, \mathcal{P}_u, \mathcal{H}_u \rangle$$
Where:
- $\text{user\_id} \in \mathcal{U}$: Unique canonical user identifier (e.g., `user_43`).
- $\mathcal{N}_u \subset \mathcal{S}_{\text{str}}$: Set of legal and preferred full names.
- $\mathcal{E}_u \subset \mathcal{S}_{\text{email}}$: Set of normalized lowercase emails (current and historical).
- $\mathcal{P}_u \subset \mathcal{S}_{\text{phone}}$: Set of normalized telephone numbers (E.164 and international spacing variations).
- $\mathcal{H}_u \subset \mathcal{S}_{\text{sha256}}$: Set of SHA-256 hashes of all email addresses.

### 3.2 Inverted Index Reconstruction

Let $\mathcal{D}_{\text{identities}}$ be `dataset/user_identities.csv` and $\mathcal{D}_{\text{audit}}$ be `dataset/user_audit_log.csv`.

1. **Base Initialization from Snapshot:**
   For each record $r \in \mathcal{D}_{\text{identities}}$:
   $$\text{uid} = r[\text{'user\_id'}]$$
   $$\mathcal{E}_u \leftarrow \{\text{lower}(r[\text{'email'}].\text{strip}())\}$$
   $$\mathcal{N}_u \leftarrow \{r[\text{'name'}].\text{strip}()\}$$
   $$\mathcal{P}_u \leftarrow \{r[\text{'phone'}].\text{strip}()\}$$
   $$\mathcal{H}_u \leftarrow \{r[\text{'email\_hash'}].\text{strip}(), \text{SHA256}(\text{lower}(r[\text{'email'}].\text{strip}()))\}$$

2. **Historical Ingestion from Audit Log:**
   For each audit record $a \in \mathcal{D}_{\text{audit}}$:
   $$\text{uid} = a[\text{'user\_id'}]$$
   - If $a[\text{'field\_name'}] == \text{'email'}$:
     $$\mathcal{E}_u \leftarrow \mathcal{E}_u \cup \{\text{lower}(a[\text{'old\_value'}]), \text{lower}(a[\text{'new\_value'}])\}$$
     $$\mathcal{H}_u \leftarrow \mathcal{H}_u \cup \{\text{SHA256}(\text{lower}(a[\text{'old\_value'}])), \text{SHA256}(\text{lower}(a[\text{'new\_value'}]))\}$$
   - If $a[\text{'field\_name'}] == \text{'phone'}$:
     $$\mathcal{P}_u \leftarrow \mathcal{P}_u \cup \{a[\text{'old\_value'}].\text{strip}(), a[\text{'new\_value'}].\text{strip}()\}$$
   - If $a[\text{'field\_name'}] == \text{'email\_hash'}$:
     $$\mathcal{H}_u \leftarrow \mathcal{H}_u \cup \{a[\text{'old\_value'}].\text{strip}(), a[\text{'new\_value'}].\text{strip}()\}$$

3. **Collision Invariant:**
   Across the entire dataset, the mapping:
   $$f: e \mapsto \text{user\_id} \quad (\forall e \in \bigcup_{u} \mathcal{E}_u)$$
   is mathematically bijective ($|\{u \mid e \in \mathcal{E}_u\}| = 1$). Zero collisions exist across users.

---

## 4. Temporal State Machine & Causality

### 4.1 Strict Temporal Boundaries

Every evaluation request $C$ specifies:
- $T_{\text{requested}}$: Request submission timestamp.
- $T_{\text{reported}}$: Workflow completion claim timestamp.
- $T_{\text{audit}}$: Cutoff timestamp for ground truth evaluation (`audit_at`).

### 4.2 Inadmissibility of Future Evidence

For any evidence item $e$ with capture timestamp $T_{\text{capture}}(e)$ and source origin:
$$e \text{ is admissible for } C \iff T_{\text{capture}}(e) \le T_{\text{audit}}(C)$$
$$\text{If } T_{\text{capture}}(e) > T_{\text{audit}}(C) \implies e \text{ MUST BE EXCLUDED}$$

### 4.3 Activity Log Temporal Windowing

In `dataset/system_activity.csv`, an activity event $a$ with timestamp $T_{\text{event}}(a)$ reflects an operational action:
$$a \text{ is admissible for } C \iff T_{\text{event}}(a) \le T_{\text{audit}}(C)$$

Operational events occurring after $T_{\text{audit}}$ cannot retroactively satisfy or invalidate the status at audit time.

---

## 5. Multi-Modal Evidence Ingestion & Unified Schema

The platform contains 94 heterogeneous evidence files across 6 primary modalities. The agent must parse and index each modality into a unified in-memory relation.

```
+---------------------------------------------------------------------------------------------------+
|                                      UNIFIED EVIDENCE SCHEMA                                      |
+-------------------+--------------------+---------------+-------------+---------------+------------+
| file_id (str)     | system_id (str)    | resource_id   | state       | matched_id    | observed_at|
| (e.g. evidence_92)| (e.g. search_serv) | (search_1993) | (e.g. PRES) | (user_or_em)  | (ISO-8601) |
+-------------------+--------------------+---------------+-------------+---------------+------------+
```

### 5.1 Modality 1: SQLite Snapshots & Replica Exports (`.sql`)

- **Files:** 24 SQL files under `dataset/evidence/databases/`.
- **Parsing Mechanism:** In-memory execution via Python's built-in `sqlite3`:
  ```python
  conn = sqlite3.connect(":memory:")
  conn.executescript(sql_text)
  ```
- **Key Tables and Ingestion Semantics:**
  1. `customer_profiles_failover_replica` vs. `customer_profiles_primary`:
     - Checks for replication drift. If a record is absent from `primary` but present in `failover_replica`, the true state is `PRESENT`.
  2. `backup_restore_entries`:
     - Columns: `(resource_id, customer_reference, customer_email, archive_key, restore_allowed, ...)`.
     - Rule: If `restore_allowed == 1` $\implies$ State is `ACTIVE` (`REPORT_RESTORE_RISK`). If `0` $\implies$ `BLOCKED`.
  3. `connector_subscriptions`:
     - Columns: `(resource_id, customer_reference, customer_email, enabled, ...)`.
     - Rule: If `enabled == 1` $\implies$ State is `ACTIVE` (`REPORT_ACTIVE_DATA_FLOW`). If `0` $\implies$ `DISABLED`.
  4. `customer_search_documents`:
     - Match query against email or subject reference. If matched $\implies$ State is `PRESENT` (`REPORT_REMAINING_RECORD`).
  5. `customer_analytics_profiles`:
     - If direct identifiers (email, phone, hash) are non-null $\implies$ State is `PRESENT` (`REPORT_EXPOSED_PII`).
     - If direct identifiers are null $\implies$ State is `ANONYMIZED`.
  6. `support_records` / `support_conversations`:
     - If message/ticket retains subject's email/phone/name $\implies$ State is `PRESENT` (`REPORT_EXPOSED_PII`).
     - If identifiers are redacted $\implies$ State is `REDACTED`.
  7. `security_audit_records`:
     - Retained security audit records $\implies$ State is `PRESENT` (`VERIFY_RECORD_PRESENT`).

### 5.2 Modality 2: Service Resource Exports (`.json`)

- **Files:** `evidence/records/service_resource_export_*.json`.
- **Top-Level Key:** `service_exports`.
- **Services Parsed:**
  - `account_service.profile_lookups`: `status_code: 200` $\implies$ `PRESENT`; `404` $\implies$ `ABSENT`.
  - `analytics_platform.profiles`: check if `email`, `phone`, `email_hash` are null (`ANONYMIZED`) vs populated (`EXPOSED_PII`).
  - `backup_service.restore_entries`: `restore_allowed == true` $\implies$ `ACTIVE`; `false` $\implies$ `BLOCKED`.
  - `export_service.exports`: matching `owner_email` $\implies$ `PRESENT` (`REPORT_REMAINING_RECORD`).
  - `integration_service.connectors`: `enabled == true` $\implies$ `ACTIVE`; `false` $\implies$ `DISABLED`.
  - `search_service.index_queries`: `hits.total > 0` $\implies$ `PRESENT` (`REPORT_REMAINING_RECORD`).
  - `security_service.audit_records`: `retention_until` active $\implies$ `PRESENT` (`VERIFY_RECORD_PRESENT`).
  - `support_platform.tickets`: `requester_email` non-null $\implies$ `PRESENT` (`REPORT_EXPOSED_PII`); null $\implies$ `REDACTED`.

### 5.3 Modality 3: Records Assurance Snapshot Bundles (`.json`)

- **Files:** `evidence/records/customer_data_snapshot_bundle_*.json`.
- **Top-Level Key:** `snapshots` array.
- **Collections:**
  - `account_service / customer_profiles`: records array empty $\implies$ `ABSENT`.
  - `identity_service / deleted_customer_references`:
    - Record structure: `{resource_id: tombstone_xxx, subject_reference: user_xxx, name, email, phone, email_hash, account_status}`.
    - If `name == null and email == null and phone == null and email_hash == null` $\implies$ `REDACTED` (Compliant Tombstone).
    - If any direct identifier is non-null $\implies$ `PRESENT` (`REPORT_EXPOSED_PII`).
  - `security_service / security_audit_events`:
    - Preserved audit records $\implies$ `PRESENT` (`VERIFY_RECORD_PRESENT`).

### 5.4 Modality 4: Structured Service Readback Logs (`.log`)

- **Files:** `evidence/logs/resource_lookup_trace_*.log`, `operations_stream_*.log`, `service_events_*.log`.
- **Format:** Key-value pairs or syslog records.
- **Attributes Extracted:** `service`, `trace_id`, `resource_id`, `lookup_key`, `subject_reference`, `rows`, `http_status`, `enabled`, `result`.
- **Semantics:**
  - `service=account_service ... rows=0 http_status=404` $\implies$ `account_*` is `ABSENT`.
  - `service=search_service ... result=hit total_hits=1` $\implies$ `search_*` is `PRESENT`.
  - `service=integration_service ... enabled=true` $\implies$ `data_flow_*` is `ACTIVE`.
  - `service=analytics_platform ... email=xxx` $\implies$ `analytics_*` has exposed PII (`PRESENT`).

### 5.5 Modality 5: Customer Shift Handover Plaintext (`.txt`)

- **Files:** `evidence/records/customer_account_handover_*.txt`.
- **Format:** Pipe-delimited records:
  ```text
  timestamp | system_id | resource_id | data_category | status | identifier
  ```
- **Status Value Mapping:**
  - `NOT_FOUND` $\implies$ `ABSENT`
  - `FOUND` (for USER_PROFILE, SEARCH_INDEX_ENTRY, SUPPORT_ATTACHMENT, USER_EXPORT) $\implies$ `PRESENT`
  - `IDENTIFIABLE` $\implies$ `PRESENT` (`REPORT_EXPOSED_PII`)
  - `ANONYMIZED` $\implies$ `ANONYMIZED`
  - `ACTIVE` (for DATA_FLOW or BACKUP_ARCHIVE) $\implies$ `ACTIVE`
  - `BLOCKED` $\implies$ `BLOCKED`
  - `DISABLED` $\implies$ `DISABLED`
  - `REDACTED` $\implies$ `REDACTED`

### 5.6 Modality 6: Document Extraction (`.pdf`)

- **Files:** `evidence/documents/*.pdf` (`delivery_correction_attachment.pdf`, `legal_retention_register_*.pdf`, `account_history_report_*.pdf`, `security_retention_extract.pdf`).
- **Structure:** ReportLab generated PDF containing ASCII85-encoded and zlib-compressed streams.
- **Deterministic Extraction Pipeline (100% Standard Library):**
  ```python
  import base64, zlib, re

  def extract_reportlab_streams(pdf_bytes: bytes) -> list[str]:
      pos = 0
      text_tokens = []
      while True:
          s_idx = pdf_bytes.find(b'stream\n', pos)
          if s_idx == -1: break
          s_start = s_idx + 7
          e_idx = pdf_bytes.find(b'endstream', s_start)
          if e_idx == -1: break
          raw = pdf_bytes[s_start:e_idx].strip()
          pos = e_idx + 9
          # Attempt ASCII85 then zlib
          try:
              if not raw.startswith(b'<~'): raw = b'<~' + raw
              if not raw.endswith(b'~>'): raw = raw + b'~>'
              a85 = base64.a85decode(raw, adobe=True)
              decomp = zlib.decompress(a85)
              for match in re.findall(rb'\((.*?)\)', decomp):
                  text_tokens.append(match.decode('latin1', errors='ignore'))
          except Exception:
              # Fallback: direct zlib
              try:
                  decomp = zlib.decompress(raw)
                  for match in re.findall(rb'\((.*?)\)', decomp):
                      text_tokens.append(match.decode('latin1', errors='ignore'))
              except Exception:
                  pass
      return text_tokens
  ```
  This extracts ticket IDs, resource IDs (`support_001`), customer names, emails, and order references without external third-party dependencies.

---

## 6. Resource Prefix to System ID Mapping

Every resource prefix in the Northstar Shop architecture maps strictly 1-to-1 to an authoritative `system_id`:

| Resource Prefix | Authoritative `system_id` | Underlying Data Category |
|---|---|---|
| `account_*` | `account_service` | `USER_PROFILE` |
| `analytics_*` | `analytics_platform` | `ANALYTICS_PROFILE` / `PRODUCT_TELEMETRY` |
| `backup_*` | `backup_service` | `BACKUP_ARCHIVE` |
| `export_*` | `export_service` | `USER_EXPORT` |
| `tombstone_*` | `identity_service` | `ACCOUNT_TOMBSTONE` |
| `data_flow_*` | `integration_service` | Active Synchronization Connector |
| `search_*` | `search_service` | `SEARCH_INDEX_ENTRY` |
| `audit_record_*` | `security_service` | `SECURITY_AUDIT_LOG` |
| `support_*` | `support_platform` | `SUPPORT_MESSAGE` or `SUPPORT_ATTACHMENT` |

---

## 7. Deletion & Retention Rule Matrix

Based on `dataset/deletion_rules.csv`, the following transition functions govern every discovered resource:

```
+----------------------------------------------------------------------------------------------------+
|                                    DELETION & RETENTION MATRIX                                     |
+---------------------+-----------------------+--------------------+----------------+----------------+
| System ID           | Category / Condition  | Finding Operation  | Remediation Op | Verification Op|
+---------------------+-----------------------+--------------------+----------------+----------------+
| account_service     | USER_PROFILE          | REPORT_REMAINING   | DELETE_RECORD  | VERIFY_RECORD  |
|                     |                       | _RECORD (PRESENT)  | (ABSENT)       | _ABSENT        |
+---------------------+-----------------------+--------------------+----------------+----------------+
| search_service      | SEARCH_INDEX_ENTRY    | REPORT_REMAINING   | DELETE_RECORD  | VERIFY_RECORD  |
|                     |                       | _RECORD (PRESENT)  | (ABSENT)       | _ABSENT        |
+---------------------+-----------------------+--------------------+----------------+----------------+
| export_service      | USER_EXPORT           | REPORT_REMAINING   | DELETE_RECORD  | VERIFY_RECORD  |
|                     |                       | _RECORD (PRESENT)  | (ABSENT)       | _ABSENT        |
+---------------------+-----------------------+--------------------+----------------+----------------+
| support_platform    | SUPPORT_ATTACHMENT    | REPORT_REMAINING   | DELETE_RECORD  | VERIFY_RECORD  |
|                     |                       | _RECORD (PRESENT)  | (ABSENT)       | _ABSENT        |
+---------------------+-----------------------+--------------------+----------------+----------------+
| support_platform    | SUPPORT_MESSAGE       | REPORT_EXPOSED     | REDACT_RECORD  | VERIFY_RECORD  |
|                     | (Shared context)      | _PII (PRESENT)     | (REDACTED)     | _REDACTED      |
+---------------------+-----------------------+--------------------+----------------+----------------+
| analytics_platform  | ANALYTICS_PROFILE     | REPORT_EXPOSED     | ANONYMIZE      | VERIFY_RECORD  |
|                     | / TELEMETRY           | _PII (PRESENT)     | _RECORD        | _ANONYMIZED    |
+---------------------+-----------------------+--------------------+----------------+----------------+
| integration_service | DATA_FLOW             | REPORT_ACTIVE      | DISABLE_DATA   | VERIFY_DATA    |
|                     | (Active Connector)    | _DATA_FLOW (ACTIVE)| _FLOW(DISABLED)| _FLOW_DISABLED |
+---------------------+-----------------------+--------------------+----------------+----------------+
| backup_service      | BACKUP_ARCHIVE        | REPORT_RESTORE     | BLOCK_RESTORE  | VERIFY_RESTORE |
|                     | (Restore Unblocked)   | _RISK (ACTIVE)     | (BLOCKED)      | _BLOCKED       |
+---------------------+-----------------------+--------------------+----------------+----------------+
| identity_service    | ACCOUNT_TOMBSTONE     | REPORT_EXPOSED     | REDACT_RECORD  | VERIFY_RECORD  |
|                     | (Direct PII exposed)  | _PII (PRESENT)     | (REDACTED)     | _REDACTED      |
+---------------------+-----------------------+--------------------+----------------+----------------+
| security_service    | SECURITY_AUDIT_LOG    | NONE (Retained     | NONE           | VERIFY_RECORD  |
|                     | / LEGAL_HOLD          | by policy)         |                | _PRESENT       |
+---------------------+-----------------------+--------------------+----------------+----------------+
```

### 7.1 Special Rules on Account Tombstones & Retained References

- Under Rule 15: An account tombstone (`tombstone_*`) is preserved in `identity_service` so downstream audit logs and legal hold records can maintain a foreign key reference to `subject_reference` (e.g., `user_541`).
- **Compliance Check:**
  $$\text{IsCompliant}(T) \iff (T.\text{name} \text{ is Null}) \land (T.\text{email} \text{ is Null}) \land (T.\text{phone} \text{ is Null}) \land (T.\text{email\_hash} \text{ is Null})$$
- If any direct identifier remains:
  - Generate `FINDING`: `REPORT_EXPOSED_PII` on `identity_service` (state: `PRESENT`).
  - Generate `REMEDIATION`: `REDACT_RECORD` on `identity_service` (state: `REDACTED`).
  - Post-remediation `VERIFICATION`: `VERIFY_RECORD_REDACTED` on `identity_service` (state: `REDACTED`).

---

## 8. Grounding & Evidence Citation Mechanics

### 8.1 Evidence Citation Principles

1. **In `INCOMPLETE` Cases:**
   - Every `FINDING` step must cite the authoritative participant-visible `evidence_id` proving the non-compliant state.
   - Proposed `REMEDIATION` steps describe future planned work $\implies$ `evidence_id: ""`.
   - Post-remediation `VERIFICATION` steps describe future checks $\implies$ `evidence_id: ""`.

2. **In `COMPLETE` Cases:**
   - There are zero `FINDING` steps and zero `REMEDIATION` steps.
   - Every `VERIFICATION` step must cite the authoritative participant-visible `evidence_id` that established the record's compliant state at $T \le T_{\text{audit}}$.

3. **In `NOT_APPLICABLE` Cases:**
   - No findings, no remediation, no verification. Output is `[]`.

### 8.2 Evidence Disambiguation Algorithm

When multiple evidence files contain observations of the subject's records at $T \le T_{\text{audit}}$, the agent selects the evidence file using the following precedence:
1. **Direct Snapshot Coverage:** If a consolidated snapshot bundle (`records_assurance_snapshot_bundle`, e.g., `evidence_51`), readback trace (`service_readback_logs`, e.g., `evidence_94`), or service export (`service_resource_export`, e.g., `evidence_92`) contains the record, select that file.
2. **Proximity to $T_{\text{audit}}$:** Among candidate files observing the specific record, select the file with the largest capture timestamp $\le T_{\text{audit}}$:
   $$e^* = \arg\max_{e \in \mathcal{E}_{\text{candidate}}} T_{\text{capture}}(e) \quad \text{s.t.} \quad T_{\text{capture}}(e) \le T_{\text{audit}}$$

---

## 9. Deterministic Step Sequencing & Tie-Breaking

### 9.1 Phase Order Precedence

All steps within `steps_json` must be strictly partitioned and sequenced across 3 sequential phases:
$$\text{Phase 1: FINDING} \longrightarrow \text{Phase 2: REMEDIATION} \longrightarrow \text{Phase 3: VERIFICATION}$$

### 9.2 Operation Order Precedence

Within each phase, operations must strictly follow the canonical challenge hierarchy:

```python
OP_ORDER = {
    # Phase 1: FINDING
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,

    # Phase 2: REMEDIATION
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,

    # Phase 3: VERIFICATION
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}
```

### 9.3 Secondary and Tertiary Tie-Breaking

If multiple steps share the same `phase` and `operation`:
1. Sort by `system_id` in ascending lexicographical order (`system_id ASC`).
2. Sort by `resource_id` in ascending lexicographical order (`resource_id ASC`).

### 9.4 Mathematical Comparator Function

For any step object $S$:
$$\text{Key}(S) = \big( \text{PhaseOrder}(S[\text{'phase'}]), \; \text{OP\_ORDER}[S[\text{'operation'}]], \; S[\text{'system\_id'}], \; S[\text{'resource\_id'}] \big)$$

After sorting the step collection using $\text{Key}(S)$, step numbers are assigned consecutively starting from 1:
$$S_i[\text{'step\_no'}] = i + 1 \quad (\forall i \in [0, N-1])$$

*Verification against 32 Sample Cases:* This exact comparator matches all 193 sample steps with 100% precision.

---

## 10. Phase 2 Implementation Architecture

The Phase 2 implementation will be built in Python 3 (standard library only, zero external packages, ensuring 100% portability in the evaluation sandbox).

```
code/
├── main.py                     # Entry point & CLI orchestrator
├── architecture_spec.md        # This formal specification
├── core/
│   ├── __init__.py
│   ├── classifier.py           # Intent classification engine
│   ├── identity.py             # Bijective identity graph resolver
│   ├── temporal.py             # Time-cutoff & causality manager
│   ├── evidence_loader.py      # SQLite, JSON, Log, & PDF multi-modal parsers
│   ├── state_reconstructor.py  # Evidence-backed resource state reconciler
│   ├── policy_engine.py        # Deletion rules & transition state machine
│   └── sequencer.py            # Deterministic sorting & JSON serialization
└── evaluation/
    ├── evaluation_report.md    # Verification metrics & custom cases
    └── usage_report.md         # Token usage & compute cost audit
```

### 10.1 Module Contracts & API Specifications

1. **`core.classifier.classify_intent(request_text: str) -> bool`**
   - Returns `True` if intent is `DELETION`, `False` if `NOT_APPLICABLE`.
   - Uses multi-lingual regex with negative-lookahead boundary checks.

2. **`core.identity.IdentityGraph`**
   - Ingests `dataset/user_identities.csv` and `dataset/user_audit_log.csv`.
   - Method `resolve_user(email: str) -> UserProfile`: Returns normalized identifiers, email hashes, and user_id.

3. **`core.evidence_loader.EvidenceRegistry`**
   - Ingests `dataset/evidence_files.csv` and pre-indexes evidence contents.
   - Decodes ASCII85+Flate ReportLab PDFs, executes SQLite SQL schemas in-memory, parses JSON exports and log lines.
   - Query method: `get_observations(user_profile: UserProfile, cutoff_iso: str) -> list[Observation]`.

4. **`core.policy_engine.evaluate_case(user_profile: UserProfile, observations: list[Observation], request: RequestRow) -> CaseResult`**
   - Applies `deletion_rules.csv`.
   - Identifies tombstones, data flows, restore risks, remaining records, and exposed PII.
   - Synthesizes findings, remediation, and verification steps.

5. **`core.sequencer.format_steps(raw_steps: list[StepDict]) -> str`**
   - Sorts via `(PhaseOrder, OpOrder, system_id, resource_id)`.
   - Assigns 1-based sequential `step_no`.
   - Emits compact, canonical JSON array string.

---

## 11. Edge Cases & Verification Invariants

1. **Replication Drift:**
   When a user profile was deleted from `customer_profiles_primary` but remains in `customer_profiles_failover_replica`, the true state is `PRESENT`. The agent must flag `REPORT_REMAINING_RECORD` on `account_service`.

2. **Tombstone PII Scrubbing:**
   When an account is deleted and `identity_service` stores a tombstone record, the `subject_reference` (e.g. `user_541`) must be retained, but all direct identifiers (`name`, `email`, `phone`, `email_hash`) must be null. If any direct identifier is present, it is an exposed PII finding.

3. **Active Connector Re-creation Risk:**
   If `integration_service` has an enabled connector (`enabled: true`) matching the user's email or reference, it is an active data flow risk (`REPORT_ACTIVE_DATA_FLOW`). Remediation must disable the flow before dependent downstream records are remediated.

4. **Backup Restore Risk:**
   If `backup_service` reports an archive where `restore_allowed: true`, it is a restore risk (`REPORT_RESTORE_RISK`). Remediation must block the restore (`BLOCK_RESTORE`).

5. **Strict Evidence Time Filtering:**
   Evidence files or activity log rows captured with `timestamp > audit_at` must never be cited or used to alter the case's status.
