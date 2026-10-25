import os
import sys
import csv
import json
import argparse
from typing import Optional

# Ensure './code' is on sys.path
sys_path_dir = os.path.dirname(os.path.abspath(__file__))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)

from core.auditor import DeletionAuditor
from core.sequencer import steps_to_json


def run_audit(
    dataset_dir: str = "dataset",
    input_file: Optional[str] = None,
    output_file: Optional[str] = None
) -> None:
    if input_file is None:
        input_file = os.path.join(dataset_dir, "deletion_requests.csv")
    if output_file is None:
        output_file = "output.csv"

    print(f"Initializing DeletionAuditor from dataset directory: {dataset_dir}...")
    auditor = DeletionAuditor(dataset_dir)

    print(f"Reading requests from: {input_file}...")
    with open(input_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    print(f"Processing {len(requests)} requests...")
    results = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for req in requests:
        cid = req["case_id"]
        status, steps = auditor.audit_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1
        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_to_json(steps)
        })

    # Sort results by numeric case_id where applicable
    def case_sort_key(item: dict) -> int:
        cid_str = item["case_id"]
        try:
            return int(cid_str.split("_")[1])
        except Exception:
            return 999999

    results.sort(key=case_sort_key)

    print(f"Writing {len(results)} rows to: {output_file}...")
    with open(output_file, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            writer.writerow([r["case_id"], r["deletion_status"], r["steps_json"]])

    print("Audit run complete!")
    print(f"Summary: Total={len(results)} | Complete={status_counts['COMPLETE']} | Incomplete={status_counts['INCOMPLETE']} | Not Applicable={status_counts['NOT_APPLICABLE']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists: AI Deletion-Audit Engine")
    parser.add_argument("--dataset-dir", default="dataset", help="Path to dataset directory")
    parser.add_argument("--input", default=None, help="Path to input deletion requests CSV")
    parser.add_argument("--output", default=None, help="Path to output CSV")
    args = parser.parse_args()

    run_audit(
        dataset_dir=args.dataset_dir,
        input_file=args.input,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
