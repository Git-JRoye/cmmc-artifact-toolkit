"""Microsoft Defender for Endpoint TVM remediation task collector.

Collects remediation activities from MDE's /api/remediationTasks — the
structured, tracked record of remediation actions created in response to
TVM vulnerability findings. This is the COMPLEMENT to
MdeVulnerabilityCollector: that collector shows what vulnerabilities
EXIST; this one shows what's being DONE about them.

CMMC practice mapping:
  RA.L2-3.11.3 — Vulnerability Remediation (DIRECT): remediation tasks
    with status tracking (Active/Completed), completion deadlines,
    and per-device progress (completedDevices/totalDevices) are exactly
    what the practice asks for: "remediate vulnerabilities in accordance
    with risk assessments." The task structure shows prioritized,
    tracked remediation — not just "we know about the vuln."
  SI.L1-3.14.1 — Flaw Remediation (SUPPORTING): remediation tasks for
    software vulnerabilities are a form of flaw correction, though
    SI.L1-3.14.1 is broader (covers all system flaws, not just CVEs).
  CA.L2-3.12.2 — Plan of Action (SUPPORTING): TVM remediation tasks
    are functionally equivalent to a subset of POA&M items — tracked,
    prioritized, deadline-bearing corrective actions. Not the full
    POA&M the practice requires, but direct evidence that the
    organization maintains and acts on corrective plans for its
    vulnerability findings.

Key fields pulled:
  id — remediation task identifier
  title — human-readable description of the remediation action
  status — Active, Completed, Expired, etc.
  type — SoftwareUpdate, ConfigurationChange, etc.
  requesterEmail — who created the task
  createdOn — when
  requestedOn — when the fix was requested
  completionDeadline — target date
  completedDevices, totalDevices — progress tracking

WindowsDefenderATP application permission: RemediationTasks.Read.All

HONEST CONFIDENCE NOTE: /api/remediationTasks is documented in
Microsoft's MDE API reference, but this collector has not been tested
against a live tenant. Field names (especially completedDevices/
totalDevices vs. possible alternatives like fixedDevicesCount/
totalDevicesCount) are recalled with moderate confidence. The response
body is logged on any error for real-pilot diagnostics.
"""

import logging
from typing import List

from ..base import CollectorBase
from ...models.artifacts import SecurityEvent
from ...cloud.graph import MdeClient

logger = logging.getLogger(__name__)


class MdeRemediationCollector(CollectorBase):
    """Collects TVM remediation task lifecycle data from the MDE API."""

    def __init__(self, mde: MdeClient, max_tasks: int = 2000):
        self.mde = mde
        self.max_tasks = max_tasks

    def collect(self) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        try:
            events = self._collect_remediation_tasks()
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("MDE remediation task collection failed: %s | Response: %s",
                             e, detail[:500])
            else:
                logger.error("MDE remediation task collection failed: %s", e)
        logger.info("MDE remediation task collection complete: %d task(s)", len(events))
        return events

    def _collect_remediation_tasks(self) -> List[SecurityEvent]:
        out: List[SecurityEvent] = []
        for record in self.mde.get_all("api/remediationTasks"):
            out.append(self._map_remediation_task(record))
            if len(out) >= self.max_tasks:
                logger.warning(
                    "  MDE remediation task cap (%d) reached — more may exist",
                    self.max_tasks,
                )
                break
        logger.info("  MDE remediation tasks: %d", len(out))
        return out

    @staticmethod
    def _map_remediation_task(record: dict) -> SecurityEvent:
        title = record.get("title") or "Untitled remediation task"
        status = record.get("status") or "Unknown"
        task_type = record.get("type") or "Unknown"
        requester = record.get("requesterEmail") or ""
        deadline = record.get("completionDeadline") or ""

        # Progress tracking — the evidence that remediation is actively
        # being worked, not just created and forgotten.
        completed = record.get("completedDevices")
        total = record.get("totalDevices")
        progress = ""
        if completed is not None and total is not None:
            progress = f" ({completed}/{total} devices)"
        elif record.get("fixedDevicesCount") is not None:
            # Fallback field name hypothesis if the primary names are wrong
            completed = record.get("fixedDevicesCount")
            total = record.get("totalDevicesCount")
            if completed is not None and total is not None:
                progress = f" ({completed}/{total} devices)"

        message_parts = [
            f"[TVM Remediation] {title}",
            f"Status: {status}",
            f"Type: {task_type}",
        ]
        if progress:
            message_parts.append(f"Progress: {progress.strip()}")
        if deadline:
            message_parts.append(f"Deadline: {deadline}")
        if requester:
            message_parts.append(f"Requester: {requester}")
        message = " | ".join(message_parts)

        return SecurityEvent(
            event_id=0,
            source="MDE TVM Remediation Tasks",
            timestamp=record.get("createdOn") or record.get("requestedOn") or "",
            message=message,
            level="Information",
            computer="N/A (tenant-level remediation task)",
            user=requester or None,
            event_data={
                "remediation_task_id": record.get("id"),
                "title": title,
                "status": status,
                "type": task_type,
                "requester_email": requester,
                "created_on": record.get("createdOn"),
                "requested_on": record.get("requestedOn"),
                "completion_deadline": deadline,
                "completed_devices": completed,
                "total_devices": total,
                "related_component": record.get("relatedComponent"),
                "target_devices": record.get("targetDevices"),
                "category": record.get("category"),
                "description": record.get("description"),
            },
        )
