"""Evaluation runner for Ghost Data Still Exists.
Compares predictions against ground truth for sample requests or custom test sets.
"""

import os
import sys
import csv
import json

# Add code/ to sys.path
sys_path_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)

from core.auditor import DeletionAuditor
from core.sequencer import steps_to_json


def evaluate_samples(dataset_dir: str = "dataset") -> None:
    sample_req_path = os.path.join(dataset_dir, "sample_deletion_requests.csv")
    sample_gt_path = os.path.join(dataset_dir, "sample_output.csv")

    if not os.path.exists(sample_req_path) or not os.path.exists(sample_gt_path):
        print(f"Sample files not found in {dataset_dir}")
        return

    print("=" * 70)
    print("Ghost Data Still Exists: Evaluation Benchmark Runner")
    print("=" * 70)

    print(f"Loading ground truth from: {sample_gt_path}...")
    with open(sample_gt_path, mode="r", encoding="utf-8") as f:
        ground_truth = {r["case_id"]: r for r in csv.DictReader(f)}

    print(f"Initializing DeletionAuditor from: {dataset_dir}...")
    auditor = DeletionAuditor(dataset_dir)

    print(f"Reading sample requests from: {sample_req_path}...")
    with open(sample_req_path, mode="r", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    status_matches = 0
    step_exact_matches = 0
    phase_order_matches = 0
    field_validity_count = 0
    total_steps_evaluated = 0

    valid_phases = {"FINDING", "REMEDIATION", "VERIFICATION"}
    valid_states = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}

    for req in requests:
        cid = req["case_id"]
        pred_status, pred_steps = auditor.audit_case(req)
        gt = ground_truth.get(cid)
        if not gt:
            continue

        gt_status = gt["deletion_status"]
        gt_steps = json.loads(gt["steps_json"])

        # Status check
        if pred_status == gt_status:
            status_matches += 1

        # Step exact match
        if pred_steps == gt_steps:
            step_exact_matches += 1

        # Check step-level schema compliance and ordering
        phases_in_order = True
        last_phase_val = 0
        phase_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

        for s in pred_steps:
            total_steps_evaluated += 1
            curr_val = phase_map.get(s["phase"], 0)
            if curr_val < last_phase_val:
                phases_in_order = False
            last_phase_val = curr_val

            # Field checks
            if (s["phase"] in valid_phases and 
                s["state"] in valid_states and 
                isinstance(s["step_no"], int) and 
                s["step_no"] > 0):
                field_validity_count += 1

        if phases_in_order:
            phase_order_matches += 1

    total_cases = len(requests)
    print("\nBenchmark Results Summary:")
    print("-" * 50)
    print(f"Total Sample Cases:         {total_cases}")
    print(f"Case Status Accuracy:       {status_matches}/{total_cases} ({(status_matches/total_cases)*100:.1f}%)")
    print(f"Phase Sequence Accuracy:    {phase_order_matches}/{total_cases} ({(phase_order_matches/total_cases)*100:.1f}%)")
    print(f"Step Exact Matches:         {step_exact_matches}/{total_cases} ({(step_exact_matches/total_cases)*100:.1f}%)")
    print(f"Field Schema Compliance:    {field_validity_count}/{total_steps_evaluated} ({(field_validity_count/max(1, total_steps_evaluated))*100:.1f}%)")
    print("=" * 70)


if __name__ == "__main__":
    evaluate_samples()
