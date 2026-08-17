"""Microsoft Defender for Endpoint alert collector.

Collects MDE alerts from the dedicated Defender for Endpoint API
(/api/alerts), NOT the Graph Security API's security/alerts_v2 endpoint
that CloudSecurityEventCollector already pulls — they are genuinely
different data sources that happen to surface related signals:

  - security/alerts_v2 (Graph) — unified alert aggregation across ALL
    Microsoft security products (Defender for Endpoint, Office 365,
    Identity, Sentinel). Broader but shallower: typically shows the
    detection without the MDE-specific investigation lifecycle.

  - /api/alerts (MDE) — Defender for Endpoint's OWN alert pipeline.
    Narrower (MDE detections only) but deeper: includes investigation
    state, resolution status, classification (true positive / false
    positive / informational), determination, assigned-to, and the
    full evidence chain (process, file, network, registry) — the exact
    investigation-to-resolution lifecycle an assessor reviewing
    SI.L2-3.14.3 and IR.L2-3.6.1 wants to see evidence of.

Both are collected deliberately — they serve different assessment
objectives. The Graph alerts prove monitoring is happening (AU.L2-3.3.1
supporting evidence, already mapped). The MDE alerts prove alert
lifecycle management: was the alert investigated, classified, resolved?
That's the "take action in response" half of SI.L2-3.14.3, and it's
directly relevant to IR.L2-3.6.1's incident handling evidence.

CMMC practice mapping:
  SI.L2-3.14.3 — Security Alerts & Advisories (DIRECT): MDE alerts
    with investigation/resolution lifecycle prove "monitor alerts AND
    take action in response" — both halves of the practice.
  SI.L2-3.14.6 — Monitor Communications for Attacks (SUPPORTING): MDE
    detects network-level attack patterns (C2 beaconing, lateral
    movement, exploitation) — partial evidence toward the practice's
    broader "monitor inbound and outbound communications" scope.
  IR.L2-3.6.1 — Incident Handling (SUPPORTING): the investigation
    lifecycle (New → InProgress → Resolved, with classification and
    determination) is direct evidence of incident handling capability,
    but the practice also requires documented procedures, roles, and
    a full IR plan that this data alone can't satisfy.
  SI.L2-3.14.7 — Identify Unauthorized Use (SUPPORTING): behavioral
    alerts (anomalous process execution, credential abuse, suspicious
    sign-in activity) serve as evidence that unauthorized use IS being
    identified, though the practice also expects a definition of what
    constitutes authorized vs. unauthorized use.

Key fields pulled (all real, documented MDE Machine resource fields):
  id, title, severity, status, classification, determination,
  investigationState, assignedTo, resolvedTime, firstEventTime,
  lastEventTime, machineId, computerDnsName, category, description

WindowsDefenderATP application permission required: Alert.Read.All
(NOT the Graph SecurityAlert.Read.All — that's a different API entirely).

HONEST CONFIDENCE NOTE: /api/alerts is a long-stable, well-documented
MDE API endpoint — materially higher confidence than newer MDE endpoints
(configuration assessment, baseline). The field names read here are
documented in Microsoft's public MDE API reference. However, the exact
$filter syntax MDE accepts (if any) on this endpoint is not independently
confirmed — this collector uses $filter with alertCreationTime as the
date field (the documented field name on the Alert resource), but if
that fails, the fallback is to fetch without a filter and client-side
date-filter instead (same defensive pattern used for sanitization events
in cloud_event_collector.py).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from ..base import CollectorBase
from ...models.artifacts import SecurityEvent
from ...cloud.graph import MdeClient

logger = logging.getLogger(__name__)

_SEVERITY_TO_LEVEL = {
    "High": "Critical",
    "Medium": "Error",
    "Low": "Warning",
    "Informational": "Information",
}


class MdeAlertCollector(CollectorBase):
    """Collects Microsoft Defender for Endpoint alerts with full
    investigation/resolution lifecycle via the MDE API."""

    def __init__(self, mde: MdeClient, lookback_hours: int = 168, max_alerts: int = 2000):
        self.mde = mde
        self.lookback_hours = lookback_hours
        self.max_alerts = max_alerts

    def collect(self) -> List[SecurityEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: List[SecurityEvent] = []
        try:
            events = self._collect_alerts(cutoff_iso)
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("MDE alert collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("MDE alert collection failed: %s", e)
        logger.info("MDE alert collection complete: %d alert(s)", len(events))
        return events

    def _collect_alerts(self, cutoff_iso: str) -> List[SecurityEvent]:
        out: List[SecurityEvent] = []

        # Attempt server-side date filter first. alertCreationTime is the
        # documented date field on the MDE Alert resource. If the MDE API
        # rejects this $filter, the except block falls back to unfiltered
        # fetch with client-side date filtering.
        try:
            params = {"$filter": f"alertCreationTime ge {cutoff_iso}", "$top": "10000"}
            for record in self.mde.get_all("api/alerts", params=params):
                out.append(self._map_alert(record))
                if len(out) >= self.max_alerts:
                    logger.warning("  MDE alert cap (%d) reached — more may exist", self.max_alerts)
                    break
        except Exception as filter_err:
            logger.warning(
                "MDE /api/alerts $filter failed (%s) — falling back to unfiltered "
                "fetch with client-side date filtering", filter_err,
            )
            out.clear()
            for record in self.mde.get_all("api/alerts"):
                created = record.get("alertCreationTime") or ""
                if created < cutoff_iso:
                    continue
                out.append(self._map_alert(record))
                if len(out) >= self.max_alerts:
                    logger.warning("  MDE alert cap (%d) reached — more may exist", self.max_alerts)
                    break

        logger.info("  MDE alerts: %d", len(out))
        return out

    @staticmethod
    def _map_alert(record: dict) -> SecurityEvent:
        severity = record.get("severity") or "Informational"
        level = _SEVERITY_TO_LEVEL.get(severity, "Information")

        title = record.get("title") or "MDE Alert"
        status = record.get("status") or "Unknown"
        classification = record.get("classification") or ""
        determination = record.get("determination") or ""
        investigation_state = record.get("investigationState") or ""
        assigned_to = record.get("assignedTo") or ""

        # Build a human-readable message that captures the lifecycle state —
        # this is the part an assessor reviewing SI.L2-3.14.3 or IR.L2-3.6.1
        # actually reads to confirm "action was taken in response."
        message_parts = [f"[MDE] {title} — Status: {status}"]
        if classification:
            message_parts.append(f"Classification: {classification}")
        if determination:
            message_parts.append(f"Determination: {determination}")
        if investigation_state:
            message_parts.append(f"Investigation: {investigation_state}")
        if assigned_to:
            message_parts.append(f"Assigned to: {assigned_to}")
        message = " | ".join(message_parts)

        computer = record.get("computerDnsName") or "N/A"

        return SecurityEvent(
            event_id=0,
            source="Microsoft Defender for Endpoint Alerts",
            timestamp=record.get("alertCreationTime") or record.get("firstEventTime") or "",
            message=message,
            level=level,
            computer=computer,
            user=assigned_to or None,
            event_data={
                "mde_alert_id": record.get("id"),
                "title": title,
                "severity": severity,
                "status": status,
                "classification": classification,
                "determination": determination,
                "investigation_state": investigation_state,
                "assigned_to": assigned_to,
                "resolved_time": record.get("resolvedTime"),
                "first_event_time": record.get("firstEventTime"),
                "last_event_time": record.get("lastEventTime"),
                "machine_id": record.get("machineId"),
                "computer_dns_name": computer,
                "category": record.get("category"),
                "detection_source": record.get("detectionSource"),
            },
        )
