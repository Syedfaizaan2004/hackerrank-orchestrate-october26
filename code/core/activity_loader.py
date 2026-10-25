"""System Activity Loader and Deletion Workflow Matcher.

Parses dataset/system_activity.csv to reconstruct deletion workflow operations,
identifying associated resource IDs and primary account profiles.
"""

from __future__ import annotations
import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.temporal import parse_iso_datetime


@dataclass
class ActivityEvent:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


class ActivityRegistry:
    """Registry indexing global system activity records."""

    def __init__(self, activity_csv_path: str) -> None:
        self.activities: List[ActivityEvent] = []
        self.by_resource: Dict[str, List[ActivityEvent]] = defaultdict(list)
        self.deletion_worker_events: List[ActivityEvent] = []
        self._load(activity_csv_path)

    def _load(self, path: str) -> None:
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = ActivityEvent(
                    activity_id=row["activity_id"],
                    event_time=row["event_time"],
                    event_type=row["event_type"],
                    source_system=row["source_system"],
                    target_system=row["target_system"],
                    resource_id=row["resource_id"],
                    reported_result=row["reported_result"],
                    details=row["details"],
                )
                self.activities.append(event)
                self.by_resource[event.resource_id].append(event)
                if event.source_system == "deletion_worker":
                    self.deletion_worker_events.append(event)

    def get_events_for_resource(self, resource_id: str) -> List[ActivityEvent]:
        return self.by_resource.get(resource_id, [])

    def find_deletion_worker_events_near(
        self,
        reported_at_iso: str,
        max_diff_seconds: float = 7200.0,
    ) -> List[ActivityEvent]:
        """Finds deletion_worker events clustered around a case's reported_at timestamp."""
        rep_dt = parse_iso_datetime(reported_at_iso)
        if not rep_dt:
            return []

        matched = []
        for ev in self.deletion_worker_events:
            ev_dt = parse_iso_datetime(ev.event_time)
            if ev_dt and abs((rep_dt - ev_dt).total_seconds()) <= max_diff_seconds:
                matched.append(ev)

        return matched
