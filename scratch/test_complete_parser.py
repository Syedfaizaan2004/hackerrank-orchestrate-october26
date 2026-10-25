import sys
sys.path.insert(0, './code')
import os, glob, json, csv, re, sqlite3, base64, zlib
from core.identity import IdentityGraph

id_graph = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')

with open('dataset/evidence_files.csv') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

print(f"Total evidence files: {len(ev_files)}")

# Data structures:
# observations[file_id] = list of observation dicts:
# {
#   "system_id": ...,
#   "resource_id": ...,
#   "state": ...,
#   "matched_user_id": ...,
#   "details": ...
# }

observations_by_file = {}

def add_obs(fid, system_id, resource_id, state, matched_user_id, extra=None):
    if fid not in observations_by_file:
        observations_by_file[fid] = []
    observations_by_file[fid].append({
        "system_id": system_id,
        "resource_id": resource_id,
        "state": state,
        "matched_user_id": matched_user_id,
        "extra": extra or {}
    })

# 1. Parse Handover text file (evidence_03)
for fid, finfo in ev_files.items():
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
                        add_obs(fid, sys_id, res_id, status, uid, {"category": cat, "ident": ident})

print("Handover parsed.")

# 2. Parse JSON files
for fid, finfo in ev_files.items():
    if finfo['file_path'].endswith('.json'):
        path = os.path.join('dataset', finfo['file_path'])
        with open(path) as f:
            data = json.load(f)
        
        # A. service_resource_export_*.json
        if "service_exports" in data:
            exports = data["service_exports"]
            for sys_id, content in exports.items():
                if sys_id == "account_service" and "profile_lookups" in content:
                    for item in content["profile_lookups"]:
                        rid = item["resource_id"]
                        sc = item.get("status_code", 404)
                        prof = item.get("profile") or {}
                        # find user
                        em = prof.get("email")
                        user = id_graph.resolve_by_email(em) if em else None
                        state = "PRESENT" if sc == 200 else "ABSENT"
                        add_obs(fid, "account_service", rid, state, user.user_id if user else None)
                
                elif sys_id == "analytics_platform" and "profiles" in content:
                    for item in content["profiles"]:
                        rid = item["resource_id"]
                        ref = item.get("customer_reference")
                        em = item.get("email")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        # if identifiers are present -> REPORT_EXPOSED_PII (PRESENT) else ANONYMIZED
                        has_pii = bool(item.get("email") or item.get("phone") or item.get("email_hash"))
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                        add_obs(fid, "analytics_platform", rid, state, user.user_id if user else None, {"has_pii": has_pii})

                elif sys_id == "backup_service" and "restore_entries" in content:
                    for item in content["restore_entries"]:
                        rid = item["resource_id"]
                        ref = item.get("customer_reference")
                        em = item.get("customer_email")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("restore_allowed") else "BLOCKED"
                        add_obs(fid, "backup_service", rid, state, user.user_id if user else None)

                elif sys_id == "export_service" and "exports" in content:
                    for item in content["exports"]:
                        rid = item["resource_id"]
                        em = item.get("owner_email")
                        ref = item.get("customer_reference")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        add_obs(fid, "export_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "integration_service" and "connectors" in content:
                    for item in content["connectors"]:
                        rid = item["resource_id"]
                        ref = item.get("customer_reference")
                        em = item.get("customer_email")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        state = "ACTIVE" if item.get("enabled") else "DISABLED"
                        add_obs(fid, "integration_service", rid, state, user.user_id if user else None)

                elif sys_id == "search_service" and "index_queries" in content:
                    for item in content["index_queries"]:
                        rid = item["resource_id"]
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
                        add_obs(fid, "search_service", rid, state, user.user_id if user else None)

                elif sys_id == "security_service" and "audit_records" in content:
                    for item in content["audit_records"]:
                        rid = item["resource_id"]
                        ref = item.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        add_obs(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

                elif sys_id == "support_platform" and "tickets" in content:
                    for item in content["tickets"]:
                        rid = item["resource_id"]
                        ref = item.get("customer_reference")
                        em = item.get("requester_email")
                        user = id_graph.resolve_by_email(em) if em else (id_graph.get_by_user_id(ref) if ref else None)
                        has_pii = bool(em or item.get("requester_name") or item.get("requester_phone"))
                        state = "PRESENT" if has_pii else "REDACTED"
                        add_obs(fid, "support_platform", rid, state, user.user_id if user else None)

        # B. customer_data_snapshot_bundle_*.json
        elif "snapshots" in data:
            for s in data["snapshots"]:
                coll = s.get("collection")
                for rec in s.get("records", []):
                    rid = rec.get("resource_id")
                    if coll == "customer_profiles":
                        em = rec.get("email")
                        user = id_graph.resolve_by_email(em)
                        add_obs(fid, "account_service", rid, "PRESENT", user.user_id if user else None)
                    elif coll == "deleted_customer_references":
                        ref = rec.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                        state = "PRESENT" if has_pii else "REDACTED"
                        add_obs(fid, "identity_service", rid, state, user.user_id if user else None)
                    elif coll == "security_audit_events":
                        ref = rec.get("subject_reference")
                        user = id_graph.get_by_user_id(ref) if ref else None
                        add_obs(fid, "security_service", rid, "PRESENT", user.user_id if user else None)

print("JSON exports and snapshots parsed.")

# 3. Parse SQL files
for fid, finfo in ev_files.items():
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
                add_obs(fid, "account_service", r[0], "PRESENT", user.user_id if user else None)

        if "customer_search_documents" in tables:
            cur.execute("SELECT resource_id, customer_reference, email FROM customer_search_documents;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                add_obs(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "search_documents_primary" in tables:
            cur.execute("SELECT resource_id, email FROM search_documents_primary;")
            for r in cur.fetchall():
                user = id_graph.resolve_by_email(r[1])
                add_obs(fid, "search_service", r[0], "PRESENT", user.user_id if user else None)

        if "connector_subscriptions" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "DISABLED"
                add_obs(fid, "integration_service", r[0], state, user.user_id if user else None)

        if "backup_restore_entries" in tables:
            cur.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1]) or id_graph.resolve_by_email(r[2])
                state = "ACTIVE" if r[3] else "BLOCKED"
                add_obs(fid, "backup_service", r[0], state, user.user_id if user else None)

        if "security_audit_records" in tables:
            cur.execute("SELECT resource_id, subject_reference FROM security_audit_records;")
            for r in cur.fetchall():
                user = id_graph.get_by_user_id(r[1])
                add_obs(fid, "security_service", r[0], "PRESENT", user.user_id if user else None)

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
                        
                        # Determine system & state
                        sys_id = orig_sys
                        if not sys_id:
                            if rid.startswith("account_"): sys_id = "account_service"
                            elif rid.startswith("search_"): sys_id = "search_service"
                            elif rid.startswith("analytics_"): sys_id = "analytics_platform"
                            elif rid.startswith("support_"): sys_id = "support_platform"
                            elif rid.startswith("export_"): sys_id = "export_service"
                            elif rid.startswith("data_flow_"): sys_id = "integration_service"
                            elif rid.startswith("backup_"): sys_id = "backup_service"
                            elif rid.startswith("audit_record_"): sys_id = "security_service"
                        
                        state = "PRESENT"
                        if sys_id == "analytics_platform":
                            has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        
                        add_obs(fid, sys_id, rid, state, user.user_id if user else None)
                    except Exception:
                        pass
        conn.close()

print("SQL files parsed.")

# 4. Parse Log files
for fid, finfo in ev_files.items():
    if finfo['file_path'].endswith('.log'):
        path = os.path.join('dataset', finfo['file_path'])
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # Check for resource_id
                rid_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', line)
                if not rid_m: continue
                rid = rid_m.group(1)

                # Determine system_id
                sys_m = re.search(r'service=([a-zA-Z0-9_]+)', line)
                sys_id = sys_m.group(1) if sys_m else None
                if not sys_id or sys_id in ['readback_collector', 'log_router']:
                    if rid.startswith("account_"): sys_id = "account_service"
                    elif rid.startswith("search_"): sys_id = "search_service"
                    elif rid.startswith("analytics_"): sys_id = "analytics_platform"
                    elif rid.startswith("support_"): sys_id = "support_platform"
                    elif rid.startswith("export_"): sys_id = "export_service"
                    elif rid.startswith("data_flow_"): sys_id = "integration_service"
                    elif rid.startswith("backup_"): sys_id = "backup_service"
                    elif rid.startswith("audit_record_"): sys_id = "security_service"

                # Check for user identifier
                user = None
                em_m = re.search(r'(?:email|lookup_key|correlation_key|match_key|matched_value)="?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"?', line)
                if em_m:
                    user = id_graph.resolve_by_email(em_m.group(1))
                if not user:
                    ref_m = re.search(r'(?:customer_reference|subject_reference|user_id|correlation_key)="?(user_\d+)"?', line)
                    if ref_m:
                        user = id_graph.get_by_user_id(ref_m.group(1))

                # Determine state
                state = "PRESENT"
                if "rows=0" in line or "http_status=404" in line or "NOT_FOUND" in line:
                    state = "ABSENT"
                elif sys_id == "integration_service":
                    state = "ACTIVE" if "enabled=true" in line else "DISABLED"
                elif sys_id == "backup_service":
                    state = "ACTIVE" if "restore_allowed=true" in line else "BLOCKED"
                elif sys_id == "support_platform":
                    state = "PRESENT" if "event=message_pii_scan" in line or (em_m and "null" not in em_m.group(0)) else "REDACTED"
                elif sys_id == "analytics_platform":
                    has_pii = bool(em_m) and ("email=null" not in line)
                    state = "PRESENT" if has_pii else "ANONYMIZED"

                add_obs(fid, sys_id, rid, state, user.user_id if user else None)

# 5. Parse PDF files (delivery_correction_attachment.pdf, etc.)
for fid, finfo in ev_files.items():
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
                
                # Check for support_XXX
                rid_m = re.search(r'(support_\d+)', full_text)
                if rid_m:
                    rid = rid_m.group(1)
                    em_m = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', full_text)
                    user = id_graph.resolve_by_email(em_m.group(1)) if em_m else None
                    add_obs(fid, "support_platform", rid, "PRESENT", user.user_id if user else None, {"pdf": True})
            except Exception:
                pass

print("Logs and PDFs parsed.")
print(f"Total observations indexed across all files: {sum(len(v) for v in observations_by_file.values())}")

with open('dataset/sample_deletion_requests.csv') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/sample_output.csv') as f:
    sample_outs = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}

print("\n--- Evaluating against 32 Sample Cases ---")
perfect_cases = 0

for req in sample_reqs:
    cid = req['case_id']
    user = id_graph.resolve_by_email(req['email'])
    gold_status, gold_steps = sample_outs[cid]
    gold_res = {s['resource_id'] for s in gold_steps}
    gold_evs = {s['evidence_id'] for s in gold_steps if s.get('evidence_id')}

    # Find all observations for this user with captured_at <= audit_at
    audit_at = req['audit_at']
    user_obs = []
    for fid, obs_list in observations_by_file.items():
        finfo = ev_files[fid]
        if finfo['captured_at'] <= audit_at:
            for obs in obs_list:
                if obs['matched_user_id'] == user.user_id:
                    user_obs.append((fid, finfo['captured_at'], obs))

    obs_res = {o[2]['resource_id'] for o in user_obs}
    obs_evs = {o[0] for o in user_obs}
    overlap_res = gold_res.intersection(obs_res)

    match_str = "MATCH" if overlap_res == gold_res else "DIFF"
    if overlap_res == gold_res:
        perfect_cases += 1
    print(f"{cid} ({user.user_id}): gold={len(gold_res)} obs={len(obs_res)} overlap={len(overlap_res)} [{match_str}]")

print(f"\nResource recall: {perfect_cases} / 32 sample cases with 100% resource match!")
