import sys
sys.path.insert(0, './code')
import os, glob, json, csv, re, sqlite3, base64, zlib
from core.identity import IdentityGraph

id_graph = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')

with open('dataset/evidence_files.csv') as f:
    ev_manifest = {r['file_id']: r for r in csv.DictReader(f)}

print(f"Loaded {len(ev_manifest)} evidence files in manifest.")

def get_system_for_resource(rid: str) -> str:
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

records_by_user = {}

def record_observation(fid, sys_id, rid, state, uid, raw_record=None):
    if not uid:
        return
    if uid not in records_by_user:
        records_by_user[uid] = []
    
    cap_at = ev_manifest[fid]['captured_at']
    records_by_user[uid].append({
        "file_id": fid,
        "captured_at": cap_at,
        "system_id": sys_id or get_system_for_resource(rid),
        "resource_id": rid,
        "state": state,
        "raw": raw_record or {}
    })

print("Parsing all evidence files...")

# 1. Parse Text Handover (evidence_03)
for fid, finfo in ev_manifest.items():
    if finfo['file_path'].endswith('.txt'):
        path = os.path.join('dataset', finfo['file_path'])
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith('- ') and '|' in line:
                    parts = [p.strip() for p in line[2:].split('|')]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, status, ident = parts[:6]
                        user = id_graph.resolve_by_email(ident) or id_graph.get_by_user_id(ident)
                        uid = user.user_id if user else None
                        
                        state = "PRESENT"
                        if status in ["NOT_FOUND", "ABSENT"]: state = "ABSENT"
                        elif status in ["ANONYMIZED"]: state = "ANONYMIZED"
                        elif status in ["REDACTED"]: state = "REDACTED"
                        elif status in ["DISABLED"]: state = "DISABLED"
                        elif status in ["BLOCKED"]: state = "BLOCKED"
                        elif status in ["ACTIVE"]: state = "ACTIVE"
                        elif status in ["IDENTIFIABLE"]: state = "EXPOSED_PII"
                        elif status in ["FOUND"]:
                            state = "PRESENT"

                        record_observation(fid, sys_id, res_id, state, uid, {"cat": cat, "ident": ident})

# 2. Parse All JSON files
for fid, finfo in ev_manifest.items():
    if finfo['file_path'].endswith('.json'):
        path = os.path.join('dataset', finfo['file_path'])
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue
        
        # A. service_resource_export_*.json
        if "service_exports" in data:
            for sys_id, content in data["service_exports"].items():
                if sys_id == "account_service" and "profile_lookups" in content:
                    for item in content["profile_lookups"]:
                        rid = item.get("resource_id")
                        sc = item.get("status_code", 404)
                        prof = item.get("profile") or {}
                        em = prof.get("email")
                        user = id_graph.resolve_by_email(em) if em else None
                        state = "PRESENT" if sc == 200 else "ABSENT"
                        record_observation(fid, "account_service", rid, state, user.user_id if user else None)
                
                elif sys_id == "analytics_platform" and "profiles" in content:
                    for item in content["profiles"]:
                        rid = item.get("resource_id")
                        em = item.get("email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        has_pii = bool(em or item.get("phone") or item.get("email_hash"))
                        state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                        record_observation(fid, "analytics_platform", rid, state, user.user_id if user else None)

                elif sys_id == "backup_service" and "restore_entries" in content:
                    for item in content["restore_entries"]:
                        rid = item.get("resource_id")
                        em = item.get("customer_email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("restore_allowed") else "BLOCKED"
                        record_observation(fid, "backup_service", rid, state, user.user_id if user else None)

                elif sys_id == "export_service" and "exports" in content:
                    for item in content["exports"]:
                        rid = item.get("resource_id")
                        em = item.get("owner_email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        record_observation(fid, "export_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "integration_service" and "connectors" in content:
                    for item in content["connectors"]:
                        rid = item.get("resource_id")
                        em = item.get("customer_email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("enabled") else "DISABLED"
                        record_observation(fid, "integration_service", rid, state, user.user_id if user else None)

                elif sys_id == "search_service" and "index_queries" in content:
                    for item in content["index_queries"]:
                        rid = item.get("resource_id")
                        hits = item.get("hits", {})
                        total = hits.get("total", 0)
                        docs = hits.get("documents", [])
                        user = None
                        if docs:
                            em = docs[0].get("email")
                            user = id_graph.resolve_by_email(em)
                        if not user and item.get("query"):
                            user = id_graph.resolve_by_email(item.get("query"))
                        state = "PRESENT" if total > 0 else "ABSENT"
                        record_observation(fid, "search_service", rid, state, user.user_id if user else None)

                elif sys_id == "security_service" and "audit_records" in content:
                    for item in content["audit_records"]:
                        rid = item.get("resource_id")
                        ref = item.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        record_observation(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "support_platform" and "tickets" in content:
                    for item in content["tickets"]:
                        rid = item.get("resource_id")
                        em = item.get("requester_email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        has_pii = bool(em or item.get("requester_name") or item.get("requester_phone"))
                        state = "EXPOSED_PII" if has_pii else "REDACTED"
                        record_observation(fid, "support_platform", rid, state, user.user_id if user else None)

        # B. customer_data_snapshot_bundle_*.json
        elif "snapshots" in data:
            for s in data["snapshots"]:
                coll = s.get("collection")
                for rec in s.get("records", []):
                    rid = rec.get("resource_id")
                    if coll == "customer_profiles":
                        em = rec.get("email")
                        user = id_graph.resolve_by_email(em)
                        record_observation(fid, "account_service", rid, "PRESENT", user.user_id if user else None)
                    elif coll == "deleted_customer_references":
                        ref = rec.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                        state = "EXPOSED_PII" if has_pii else "REDACTED"
                        record_observation(fid, "identity_service", rid, state, user.user_id if user else None)
                    elif coll == "security_audit_events":
                        ref = rec.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        record_observation(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

        # C. Generic records array in JSON (exports, connectors, analytics)
        elif "records" in data and isinstance(data["records"], list):
            for rec in data["records"]:
                rid = rec.get("resource_id")
                em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email") or rec.get("customer_email")
                ref = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                
                # Check for active / blocked / pii
                if "restore_allowed" in rec:
                    state = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
                    record_observation(fid, "backup_service", rid, state, user.user_id if user else None)
                elif "enabled" in rec:
                    state = "ACTIVE" if rec.get("enabled") else "DISABLED"
                    record_observation(fid, "integration_service", rid, state, user.user_id if user else None)
                elif "object_key" in rec:
                    record_observation(fid, "export_service", rid, "PRESENT", user.user_id if user else None)
                elif "event_code" in rec or "retention_until" in rec:
                    record_observation(fid, "security_service", rid, "PRESENT", user.user_id if user else None)
                elif "reporting_window" in rec or "audience_cohort" in rec:
                    has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                    state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                    record_observation(fid, "analytics_platform", rid, state, user.user_id if user else None)

print("JSON parsed.")

# 3. Parse SQL files
for fid, finfo in ev_manifest.items():
    if finfo['file_path'].endswith('.sql'):
        path = os.path.join('dataset', finfo['file_path'])
        conn = sqlite3.connect(':memory:')
        with open(path) as f:
            conn.executescript(f.read())
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]

        # Failover replica customer profiles
        if "customer_profiles_failover_replica" in tables:
            cur.execute("SELECT resource_id, user_id, email FROM customer_profiles_failover_replica;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                record_observation(fid, "account_service", r[0], "PRESENT", user.user_id if user else None)

        if "customer_search_documents" in tables:
            cur.execute("SELECT resource_id, customer_reference, email FROM customer_search_documents;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                record_observation(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "search_documents_primary" in tables:
            cur.execute("SELECT resource_id, email FROM search_documents_primary;")
            for r in cur.fetchall():
                user = id_graph.resolve_by_email(r[1])
                record_observation(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "connector_subscriptions" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "DISABLED"
                record_observation(fid, "integration_service", r[0], state, user.user_id if user else None)

        if "backup_restore_entries" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "BLOCKED"
                record_observation(fid, "backup_service", r[0], state, user.user_id if user else None)

        if "security_audit_records" in tables:
            cur.execute("SELECT resource_id, subject_reference FROM security_audit_records;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1])
                record_observation(fid, "security_service", r[0], "PRESENT", user.user_id if user else None)

        # Tables with record_json
        for t in ["customer_data_read_replica", "customer_data_primary", "customer_data_reporting_replica", "customer_data_failover_replica"]:
            if t in tables:
                cur.execute(f"SELECT resource_id, origin_system, collection_name, record_json FROM {t};")
                for r in cur.fetchall():
                    rid, orig_sys, coll, r_json = r
                    try:
                        rec = json.loads(r_json)
                        em = rec.get("email") or rec.get("owner_email") or rec.get("requester_email")
                        ref = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                        user = id_graph.resolve_by_email(em) or (id_graph.get_by_user_id(ref) if ref else None)
                        
                        sys_id = orig_sys or get_system_for_resource(rid)
                        state = "PRESENT"
                        if sys_id == "analytics_platform":
                            has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                            state = "EXPOSED_PII" if has_pii else "ANONYMIZED"
                        elif sys_id == "identity_service":
                            has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                            state = "EXPOSED_PII" if has_pii else "REDACTED"
                        
                        record_observation(fid, sys_id, rid, state, user.user_id if user else None)
                    except Exception:
                        pass
        conn.close()

# 4. Parse Log files
for fid, finfo in ev_manifest.items():
    if finfo['file_path'].endswith('.log'):
        path = os.path.join('dataset', finfo['file_path'])
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', line)
                if not rid_m: continue
                rid = rid_m.group(1)
                sys_id = get_system_for_resource(rid)

                user = None
                em_m = re.search(r'(?:email|lookup_key|correlation_key|match_key|matched_value)="?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"?', line)
                if em_m:
                    user = id_graph.resolve_by_email(em_m.group(1))
                if not user:
                    ref_m = re.search(r'(?:customer_reference|subject_reference|user_id|correlation_key)="?(user_\d+)"?', line)
                    if ref_m:
                        user = id_graph.get_by_user_id(ref_m.group(1))

                state = "PRESENT"
                if "rows=0" in line or "http_status=404" in line or "NOT_FOUND" in line:
                    state = "ABSENT"
                elif sys_id == "integration_service":
                    state = "ACTIVE" if "enabled=true" in line else "DISABLED"
                elif sys_id == "backup_service":
                    state = "ACTIVE" if "restore_allowed=true" in line else "BLOCKED"
                elif sys_id == "support_platform":
                    state = "EXPOSED_PII" if "event=message_pii_scan" in line or (em_m and "null" not in em_m.group(0)) else "REDACTED"
                elif sys_id == "analytics_platform":
                    has_pii = bool(em_m) and ("email=null" not in line)
                    state = "EXPOSED_PII" if has_pii else "ANONYMIZED"

                record_observation(fid, sys_id, rid, state, user.user_id if user else None)

# 5. Parse PDF files
for fid, finfo in ev_manifest.items():
    if finfo['file_path'].endswith('.pdf'):
        path = os.path.join('dataset', finfo['file_path'])
        with open(path, 'rb') as f:
            pdf_data = f.read()
        
        pos = 0
        while True:
            s_idx = pdf_data.find(b'stream\n', pos)
            if s_idx == -1: break
            e_idx = pdf_data.find(b'endstream', s_idx)
            raw = pdf_data[s_idx+7:e_idx].strip()
            pos = e_idx + 9
            try:
                if not raw.startswith(b'<~'): raw = b'<~' + raw
                if not raw.endswith(b'~>'): raw = raw + b'~>'
                a85 = base64.a85decode(raw, adobe=True)
                dec = zlib.decompress(a85)
                texts = [t.decode('latin1') for t in re.findall(rb'\((.*?)\)\s*Tj', dec)]
                full_text = " ".join(texts)
                
                rid_m = re.search(r'(support_\d+)', full_text)
                if rid_m:
                    rid = rid_m.group(1)
                    em_m = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', full_text)
                    user = id_graph.resolve_by_email(em_m.group(1)) if em_m else None
                    record_observation(fid, "support_platform", rid, "PRESENT", user.user_id if user else None, {"attachment": True})
            except Exception:
                pass

print(f"Total users with observations: {len(records_by_user)}")
print(f"Total observations indexed: {sum(len(v) for v in records_by_user.values())}")
