"""Deterministic Step Sequencing and Formatting Module.

Enforces strict sorting order:
1. Phase order: FINDING (1) -> REMEDIATION (2) -> VERIFICATION (3)
2. Operation order (canonical problem statement hierarchy)
3. Tie-breaker 1: system_id ascending
4. Tie-breaker 2: resource_id ascending
5. Consecutive step_no starting from 1.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List

# Phase hierarchy mapping
PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

# Strict canonical operation hierarchy mapping
OPERATION_ORDER = {
    # Phase: FINDING
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,

    # Phase: REMEDIATION
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,

    # Phase: VERIFICATION
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}


def step_sort_key(step: Dict[str, Any]) -> tuple:
    """Computes comparator tuple for strict deterministic sorting."""
    phase_rank = PHASE_ORDER.get(step.get("phase", ""), 99)
    op_rank = OPERATION_ORDER.get(step.get("operation", ""), 99)
    system_id = step.get("system_id", "")
    resource_id = step.get("resource_id", "")
    return (phase_rank, op_rank, system_id, resource_id)


def sequence_and_format_steps(raw_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sorts step objects deterministically and re-numbers step_no from 1."""
    if not raw_steps:
        return []

    # Sort strictly by the comparator
    sorted_steps = sorted(raw_steps, key=step_sort_key)

    formatted = []
    for idx, s in enumerate(sorted_steps, start=1):
        formatted.append({
            "step_no": idx,
            "phase": s["phase"],
            "system_id": s["system_id"],
            "resource_id": s["resource_id"],
            "operation": s["operation"],
            "state": s["state"],
            "evidence_id": s.get("evidence_id", "") or "",
        })

    return formatted


def steps_to_json(steps: List[Dict[str, Any]]) -> str:
    """Serializes steps into compact JSON array matching the evaluation format."""
    return json.dumps(steps, separators=(",", ":"))
