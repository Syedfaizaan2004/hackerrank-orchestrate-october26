import sys
sys.path.insert(0, './code')
import csv, json, os, glob
from core.identity import IdentityGraph
from core.classifier import is_deletion_request
from core.evidence_loader import EvidenceRegistry, get_system_for_resource
from core.activity_loader import ActivityRegistry
from core.sequencer import sequence_and_format_steps, steps_to_json

id_graph = IdentityGraph('dataset/user_identities.csv', 'dataset/user_audit_log.csv')
ev_reg = EvidenceRegistry('dataset', id_graph)
act_reg = ActivityRegistry('dataset/system_activity.csv')

with open('dataset/sample_deletion_requests.csv') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/sample_output.csv') as f:
    sample_outs = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}

print(f"Loaded {len(sample_reqs)} sample requests.")

def audit_case(req):
    cid = req['case_id']
    req_text = req['request_text']
    if not is_deletion_request(req_text):
        return "NOT_APPLICABLE", []

    email = req['email']
    user = id_graph.resolve_by_email(email)
    if not user:
        return "NOT_APPLICABLE", []

    audit_at = req['audit_at']
    rep_at = req['reported_at']

    # 1. Collect all direct observations for this user with captured_at <= audit_at
    obs_by_res = {}
    for obs in ev_reg.observations:
        if obs.captured_at <= audit_at:
            if obs.matched_user_id == user.user_id:
                # pick the most recent observation for this resource
                if obs.resource_id not in obs_by_res or obs.captured_at > obs_by_res[obs.resource_id].captured_at:
                    obs_by_res[obs.resource_id] = obs

    # 2. Check deletion_worker activity near reported_at to catch primary profile or downstream resources
    acts = act_reg.find_deletion_worker_events_near(rep_at, max_diff_seconds=10800.0) # 3 hours
    for a in acts:
        rid = a.resource_id
        # if this resource hasn't been observed yet, search if any evidence <= audit_at observed it
        if rid not in obs_by_res:
            for obs in ev_reg.observations:
                if obs.captured_at <= audit_at and obs.resource_id == rid:
                    if rid not in obs_by_res or obs.captured_at > obs_by_res[rid].captured_at:
                        obs_by_res[rid] = obs

    # If account_* is not yet in obs_by_res, find the primary profile from acts
    acc_res = [r for r in obs_by_res if r.startswith("account_")]
    if not acc_res:
        acc_acts = [a for a in acts if a.target_system == "account_service"]
        if acc_acts:
            # find closest to rep_at
            acc_rid = acc_acts[0].resource_id
            # find an evidence file observing this account or failover replica <= audit_at
            for obs in ev_reg.observations:
                if obs.captured_at <= audit_at and obs.resource_id == acc_rid:
                    obs_by_res[acc_rid] = obs
                    break
            if acc_rid not in obs_by_res:
                # default absent observation citing best evidence before audit_at
                # find best evidence file
                ev_candidates = [fid for fid, f in ev_reg.manifest.items() if f['captured_at'] <= audit_at]
                best_ev = max(ev_candidates, key=lambda x: ev_reg.manifest[x]['captured_at']) if ev_candidates else "evidence_01"
                from core.evidence_loader import Observation
                obs_by_res[acc_rid] = Observation(
                    file_id=best_ev,
                    captured_at=ev_reg.manifest[best_ev]['captured_at'],
                    system_id="account_service",
                    resource_id=acc_rid,
                    state="ABSENT",
                    matched_user_id=user.user_id
                )

    # 3. Evaluate each resource
    findings = []
    remediations = []
    verifications = []

    is_incomplete = False

    for rid, obs in obs_by_res.items():
        sys_id = obs.system_id
        state = obs.state
        fid = obs.file_id

        # Rule evaluation
        if sys_id == "account_service":
            if state == "PRESENT":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "search_service":
            if state == "PRESENT":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "export_service":
            if state == "PRESENT":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "support_platform":
            is_attach = obs.extra.get("attachment") or obs.extra.get("cat") == "SUPPORT_ATTACHMENT"
            if is_attach and state == "PRESENT":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "phase": "VERIFICATION", "evidence_id": ""})
            elif state in ["EXPOSED_PII", "PRESENT"]:
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "analytics_platform":
            if state in ["EXPOSED_PII", "PRESENT"]:
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "integration_service":
            if state == "ACTIVE":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "backup_service":
            if state == "ACTIVE":
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "identity_service":
            if state in ["EXPOSED_PII", "PRESENT"]:
                is_incomplete = True
                findings.append({"system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "phase": "FINDING", "evidence_id": fid})
                remediations.append({"system_id": sys_id, "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "phase": "REMEDIATION", "evidence_id": ""})
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "phase": "VERIFICATION", "evidence_id": ""})
            else:
                verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "phase": "VERIFICATION", "evidence_id": fid})

        elif sys_id == "security_service":
            verifications.append({"system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "phase": "VERIFICATION", "evidence_id": fid})

    if is_incomplete:
        # In incomplete cases, verification steps have empty evidence_id
        for v in verifications:
            v["evidence_id"] = ""
        all_steps = findings + remediations + verifications
        return "INCOMPLETE", sequence_and_format_steps(all_steps)
    else:
        # In complete cases, only verification steps
        return "COMPLETE", sequence_and_format_steps(verifications)

print("\n--- Testing Audit Logic on 32 Samples ---")
exact_status = 0
exact_steps = 0

for req in sample_reqs:
    cid = req['case_id']
    gold_status, gold_steps = sample_outs[cid]
    pred_status, pred_steps = audit_case(req)

    status_match = (pred_status == gold_status)
    if status_match:
        exact_status += 1

    steps_match = (pred_steps == gold_steps)
    if steps_match:
        exact_steps += 1

    print(f"{cid}: Status: pred={pred_status:10s} gold={gold_status:10s} {'[OK]' if status_match else '[FAIL]'} | Steps: pred={len(pred_steps)} gold={len(gold_steps)} {'[OK]' if steps_match else '[DIFF]'}")

print(f"\nFinal Summary: Status Accuracy = {exact_status}/32 ({exact_status/32*100:.1f}%), Exact Steps Parity = {exact_steps}/32 ({exact_steps/32*100:.1f}%)")
