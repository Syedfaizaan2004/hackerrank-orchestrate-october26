"""Multi-Modal Evidence Loader & Unified In-Memory Indexer.

Ingests all 94 evidence files across 6 modalities:
1. Text handover reports (.txt)
2. Service exports and snapshot bundles (.json)
3. SQLite snapshots and replicas (.sql)
4. Structured readback and observability logs (.log)
5. ReportLab PDF document attachments (.pdf)
"""

from __future__ import annotations
import base64
import csv
import json
import os
import re
import sqlite3
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.identity import IdentityGraph, UserProfile


def get_system_for_resource(rid: str) -> str:
    """Authoritative mapping from resource prefix to system_id."""
    if rid.startswith("account_"): return "account_service"
    if rid.startswith("search_"): return "search_service"
    if rid.startswith("analytics_"): return "analytics_platform"
    if rid.startswith("support_"): return "support_platform"
    if rid.startswith("export_"): return "export_service"
    if rid.startswith("data_flow_"): return "integration_service"
    if rid.startswith("backup_"): return "backup_service"
    if rid.startswith("audit_record_"): return "security_service"
    if rid.startswith("tombstone_"): return "identity_service"
    return "unknown_service"


@dataclass
class Observation:
    file_id: str
    captured_at: str
    system_id: str
    resource_id: str
    state: str  # PRESENT, ABSENT, ACTIVE, DISABLED, BLOCKED, REDACTED, ANONYMIZED, EXPOSED_PII
    matched_user_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class EvidenceRegistry:
    """Unified in-memory registry of all evidence observations."""

    def __init__(self, dataset_dir: str, id_graph: IdentityGraph) -> None:
        self.dataset_dir = dataset_dir
        self.id_graph = id_graph
        self.manifest: Dict[str, Dict[str, str]] = {}
        self.observations: List[Observation] = []
        self._load_manifest()
        self._index_all_evidence()

    def _load_manifest(self) -> None:
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(manifest_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.manifest[row["file_id"]] = row

    def _add_obs(
        self,
        fid: str,
        sys_id: Optional[str],
        rid: str,
        state: str,
        uid: Optional[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not rid:
            return
        cap_at = self.manifest[fid]["captured_at"]
        final_sys = sys_id or get_system_for_resource(rid)
        self.observations.append(
            Observation(
                file_id=fid,
                captured_at=cap_at,
                system_id=final_sys,
                resource_id=rid,
                state=state,
                matched_user_id=uid,
                extra=extra or {},
            )
        )

    def _index_all_evidence(self) -> None:
        for fid, finfo in self.manifest.items():
            rel_path = finfo["file_path"]
            abs_path = os.path.join(self.dataset_dir, rel_path)
            if not os.path.exists(abs_path):
                continue

            ext = os.path.splitext(rel_path)[1].lower()
            if ext == ".txt":
                self._parse_txt(fid, abs_path)
            elif ext == ".json":
                self._parse_json(fid, abs_path)
            elif ext == ".sql":
                self._parse_sql(fid, abs_path)
            elif ext == ".log":
                self._parse_log(fid, abs_path)
            elif ext == ".pdf":
                self._parse_pdf(fid, abs_path)

    def _parse_txt(self, fid: str, path: str) -> None:
        with open(path, mode="r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("- ") and "|" in line:
                    parts = [p.strip() for p in line[2:].split("|")]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, status, ident = parts[:6]
                        user = self.id_graph.resolve_by_email(ident) or self.id_graph.get_by_user_id(ident)
                        uid = user.user_id if user else None

                        state = "PRESENT"
                        if status in ["NOT_FOUND", "ABSENT"]:
                            state = "ABSENT"
                        elif status in ["ANONYMIZED"]:
                            state = "ANONYMIZED"
                        elif status in ["REDACTED"]:
                            state = "REDACTED"
                        elif status in ["DISABLED"]:
                            state = "DISABLED"
                        elif status in ["BLOCKED"]:
                            state = "BLOCKED"
                        elif status in ["ACTIVE"]:
                            state = "ACTIVE"
                        elif status in ["IDENTIFIABLE"]:
                            state = "EXPOSED_PII"

                        self._add_obs(fid, sys_id, res_id, state, uid, {"cat": cat, "ident": ident})

    def _parse_json(self, fid: str, path: str) -> None:
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return

        # 1. service_resource_export_*.json
        if "service_exports" in data:
            exports = data["service_exports"]
            for sys_id, content in exports.items():
                if sys_id == "account_service" and "profile_lookups" in content:
                    for item in content["profile_lookups"]:
                        rid = item.get("resource_id")
                        sc = item.get("status_code", 404)
                        prof = item.get("profile") or {}
                        em = prof.get("email")
                        user = self.id_graph.resolve_by_email(em) if em else None
                        state = "PRESENT" if sc == 200 else "ABSENT"
                        self._add_obs(fid, "account_service", rid, state, user.user_id if user else None)

                elif sys_id == "analytics_platform" and "profiles" in content:
                    for item in content["profiles"]:
                        rid = item.get("resource_id")
                        em = item.get("email")
                        ref = item.get("customer_reference")
                        user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)
                        has_pii = bool(em or item.get("phone") or item.get("email_hash"))
                        state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                        self._add_obs(fid, "analytics_platform", rid, state, user.user_id if user else None)

                elif sys_id == "backup_service" and "restore_entries" in content:
                    for item in content["restore_entries"]:
                        rid = item.get("resource_id")
                        em = item.get("customer_email")
                        ref = item.get("customer_reference")
                        user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("restore_allowed") else "BLOCKED"
                        self._add_obs(fid, "backup_service", rid, state, user.user_id if user else None)

                elif sys_id == "export_service" and "exports" in content:
                    for item in content["exports"]:
                        rid = item.get("resource_id")
                        em = item.get("owner_email")
                        ref = item.get("customer_reference")
                        user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)
                        self._add_obs(fid, "export_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "integration_service" and "connectors" in content:
                    for item in content["connectors"]:
                        rid = item.get("resource_id")
                        em = item.get("customer_email")
                        ref = item.get("customer_reference")
                        user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("enabled") else "DISABLED"
                        self._add_obs(fid, "integration_service", rid, state, user.user_id if user else None)

                elif sys_id == "search_service" and "index_queries" in content:
                    for item in content["index_queries"]:
                        rid = item.get("resource_id")
                        hits = item.get("hits", {})
                        total = hits.get("total", 0)
                        docs = hits.get("documents", [])
                        user = None
                        if docs:
                            em = docs[0].get("email")
                            user = self.id_graph.resolve_by_email(em)
                        if not user and item.get("query"):
                            user = self.id_graph.resolve_by_email(item.get("query"))
                        state = "PRESENT" if total > 0 else "ABSENT"
                        self._add_obs(fid, "search_service", rid, state, user.user_id if user else None)

                elif sys_id == "security_service" and "audit_records" in content:
                    for item in content["audit_records"]:
                        rid = item.get("resource_id")
                        ref = item.get("subject_reference")
                        user = self.id_graph.get_by_user_id(ref) if ref else None
                        self._add_obs(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "support_platform" and "tickets" in content:
                    for item in content["tickets"]:
                        rid = item.get("resource_id")
                        em = item.get("requester_email")
                        ref = item.get("customer_reference")
                        user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)
                        has_pii = bool(em or item.get("requester_name") or item.get("requester_phone"))
                        state = "EXPOSED_PII" if has_pii else "REDACTED"
                        self._add_obs(fid, "support_platform", rid, state, user.user_id if user else None)

        # 2. customer_data_snapshot_bundle_*.json
        elif "snapshots" in data:
            for s in data["snapshots"]:
                coll = s.get("collection")
                for rec in s.get("records", []):
                    rid = rec.get("resource_id")
                    if coll == "customer_profiles":
                        em = rec.get("email")
                        user = self.id_graph.resolve_by_email(em)
                        self._add_obs(fid, "account_service", rid, "PRESENT", user.user_id if user else None)
                    elif coll == "deleted_customer_references":
                        ref = rec.get("subject_reference")
                        user = self.id_graph.get_by_user_id(ref) if ref else None
                        has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                        state = "EXPOSED_PII" if has_pii else "REDACTED"
                        self._add_obs(fid, "identity_service", rid, state, user.user_id if user else None)
                    elif coll == "security_audit_events":
                        ref = rec.get("subject_reference")
                        user = self.id_graph.get_by_user_id(ref) if ref else None
                        self._add_obs(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

        # 3. Generic records array in JSON
        elif "records" in data and isinstance(data["records"], list):
            for rec in data["records"]:
                rid = rec.get("resource_id", "")
                em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email") or rec.get("customer_email")
                ref = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                user = self.id_graph.resolve_by_email(em) if em else (self.id_graph.get_by_user_id(ref) if ref else None)

                # Schema A: Ledgers with system and result
                if "system" in rec and "result" in rec:
                    sys_id = rec.get("system")
                    res = rec.get("result")
                    state = "PRESENT" if res == "FOUND" else "ABSENT"
                    self._add_obs(fid, sys_id, rid, state, user.user_id if user else None)
                # Schema B: Restore entries
                elif "restore_allowed" in rec:
                    state = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                    self._add_obs(fid, "backup_service", rid, state, user.user_id if user else None)
                # Schema C: Connectors
                elif "enabled" in rec:
                    state = "ACTIVE" if rec.get("enabled") else "DISABLED"
                    self._add_obs(fid, "integration_service", rid, state, user.user_id if user else None)
                # Schema D: Exports
                elif rid.startswith("export_") or "object_key" in rec or "download_available" in rec or "file_name" in rec:
                    self._add_obs(fid, "export_service", rid, "PRESENT", user.user_id if user else None)
                # Schema E: Security audit records
                elif "event_code" in rec or "retention_until" in rec or rid.startswith("audit_record_"):
                    self._add_obs(fid, "security_service", rid, "PRESENT", user.user_id if user else None)
                # Schema F: Analytics profiles
                elif "reporting_window" in rec or "audience_cohort" in rec or rid.startswith("analytics_"):
                    has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash") or rec.get("user_id"))
                    state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                    self._add_obs(fid, "analytics_platform", rid, state, user.user_id if user else None)

    def _parse_sql(self, fid: str, path: str) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                conn.executescript(f.read())
        except Exception:
            conn.close()
            return

        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]

        if "customer_profiles_failover_replica" in tables:
            cur.execute("SELECT resource_id, user_id, email FROM customer_profiles_failover_replica;")
            for r in cur.fetchall():
                user = self.id_graph.get_by_user_id(r[1]) or self.id_graph.resolve_by_email(r[2])
                self._add_obs(fid, "account_service", r[0], "PRESENT", user.user_id if user else None)

        if "customer_search_documents" in tables:
            cur.execute("SELECT resource_id, customer_reference, email FROM customer_search_documents;")
            for r in cur.fetchall():
                user = self.id_graph.get_by_user_id(r[1]) or self.id_graph.resolve_by_email(r[2])
                self._add_obs(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "search_documents_primary" in tables:
            cur.execute("SELECT resource_id, email FROM search_documents_primary;")
            for r in cur.fetchall():
                user = self.id_graph.resolve_by_email(r[1])
                self._add_obs(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "connector_subscriptions" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions;")
            for r in cur.fetchall():
                user = self.id_graph.get_by_user_id(r[1]) or self.id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "DISABLED"
                self._add_obs(fid, "integration_service", r[0], state, user.user_id if user else None)

        if "backup_restore_entries" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries;")
            for r in cur.fetchall():
                user = self.id_graph.get_by_user_id(r[1]) or self.id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "BLOCKED"
                self._add_obs(fid, "backup_service", r[0], state, user.user_id if user else None)

        if "security_audit_records" in tables:
            cur.execute("SELECT resource_id, subject_reference FROM security_audit_records;")
            for r in cur.fetchall():
                user = self.id_graph.get_by_user_id(r[1])
                self._add_obs(fid, "security_service", r[0], "PRESENT", user.user_id if user else None)

        for t in ["customer_data_read_replica", "customer_data_primary", "customer_data_reporting_replica", "customer_data_failover_replica"]:
            if t in tables:
                cur.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {t};")
                for r in cur.fetchall():
                    rid, orig_sys, coll, r_json = r
                    try:
                        rec = json.loads(r_json)
                        em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email")
                        ref = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                        user = self.id_graph.resolve_by_email(em) or (self.id_graph.get_by_user_id(ref) if ref else None)

                        sys_id = orig_sys or get_system_for_resource(rid)
                        state = "PRESENT"
                        if sys_id == "analytics_platform":
                            has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                            state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                        elif sys_id == "identity_service":
                            has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                            state = "EXPOSED_PII" if has_pii else "REDACTED"

                        self._add_obs(fid, sys_id, rid, state, user.user_id if user else None)
                    except Exception:
                        pass
        conn.close()

    def _parse_log(self, fid: str, path: str) -> None:
        lines_by_trace: Dict[str, List[str]] = {}
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tr_m = re.search(r'(?:trace_id|requestId)[\"\'\s]*[=:]\s*[\"\']?([a-zA-Z0-9_-]+)', line)
                tr = tr_m.group(1) if tr_m else None
                if tr:
                    if tr not in lines_by_trace:
                        lines_by_trace[tr] = []
                    lines_by_trace[tr].append(line)
                else:
                    lines_by_trace[line] = [line]

        for tr, group in lines_by_trace.items():
            user = None
            for l in group:
                em_m = re.search(r'(?:email|lookup_key|correlation_key|match_key|matched_value|subject_key)[\"\'\s]*[=:]\s*[\"\']*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', l)
                if em_m:
                    user = self.id_graph.resolve_by_email(em_m.group(1))
                    if user:
                        break
                ref_m = re.search(r'(?:customer_reference|subject_reference|user_id|subject_ref|correlation_key)[\"\'\s]*[=:]\s*[\"\']*(user_\d+)', l)
                if ref_m:
                    user = self.id_graph.get_by_user_id(ref_m.group(1))
                    if user:
                        break
                hash_m = re.search(r'(?:correlation_key|email_hash|hash)[\"\'\s]*[=:]\s*[\"\']*([a-f0-9]{64})', l)
                if hash_m:
                    user = self.id_graph.resolve_by_hash(hash_m.group(1))
                    if user:
                        break

            joined = " ".join(group)
            rids = set(re.findall(r'resource_id[\"\'\s]*[=:]\s*[\"\']*([a-zA-Z0-9_]+)', joined))
            for rid in rids:
                sys_id = get_system_for_resource(rid)

                state = "PRESENT"
                if "rows=0" in joined or '"rows":"0"' in joined or "http_status=404" in joined or '"http_status":"404"' in joined or "NOT_FOUND" in joined:
                    state = "ABSENT"
                elif sys_id == "integration_service":
                    state = "ACTIVE" if ("enabled=true" in joined or '"enabled":true' in joined or '"enabled":"true"' in joined) else "DISABLED"
                elif sys_id == "backup_service":
                    is_active = ("restore_allowed=true" in joined or '"restore_allowed":true' in joined or '"restore_allowed":"true"' in joined or "deletion_block=false" in joined or "eligible=true" in joined)
                    state = "ACTIVE" if is_active else "BLOCKED"
                elif sys_id == "support_platform":
                    state = "EXPOSED_PII" if ("event=message_pii_scan" in joined or ('requester_email=null' not in joined and '"requester_email":null' not in joined and user)) else "REDACTED"
                elif sys_id == "analytics_platform":
                    if "email_opt_in=true" in joined:
                        state = "PRESENT"
                    else:
                        has_pii = ("email=null" not in joined and '"email":null' not in joined and user)
                        state = "EXPOSED_PII" if has_pii else "ANONYMIZED"

                self._add_obs(fid, sys_id, rid, state, user.user_id if user else None)

    def _parse_pdf(self, fid: str, path: str) -> None:
        with open(path, mode="rb") as f:
            pdf_data = f.read()

        pos = 0
        while True:
            s_idx = pdf_data.find(b"stream", pos)
            if s_idx == -1:
                break
            cur = s_idx + 6
            while cur < len(pdf_data) and pdf_data[cur] in (10, 13):
                cur += 1
            e_idx = pdf_data.find(b"endstream", cur)
            if e_idx == -1:
                break
            raw = pdf_data[cur:e_idx].strip()
            pos = e_idx + 9
            try:
                if not raw.startswith(b"<~"):
                    raw = b"<~" + raw
                if not raw.endswith(b"~>"):
                    raw = raw + b"~>"
                a85 = base64.a85decode(raw, adobe=True)
                dec = zlib.decompress(a85)
                txt = dec.decode("latin1", errors="ignore")
                strings = re.findall(r"\((.*?)\)", txt)
                full_text = " ".join(strings)

                # Search for resources
                for rid in re.findall(r"(?:support|account|export|audit_record|analytics|data_flow|backup|tombstone)_\d+", full_text):
                    sys_id = get_system_for_resource(rid)
                    em_m = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", full_text)
                    user = self.id_graph.resolve_by_email(em_m.group(1)) if em_m else None
                    if not user:
                        ref_m = re.search(r"(user_\d+)", full_text)
                        user = self.id_graph.get_by_user_id(ref_m.group(1)) if ref_m else None

                    is_attachment = ("delivery_address_correction" in full_text or "attachment" in full_text.lower())
                    self._add_obs(fid, sys_id, rid, "PRESENT", user.user_id if user else None, {"attachment": is_attachment})
            except Exception:
                pass
