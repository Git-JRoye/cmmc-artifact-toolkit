"""Microsoft Defender for Endpoint alert AND incident collector.

Collects MDE alerts from the dedicated Defender for Endpoint API
(/api/alerts) AND MDE incidents (/api/incidents), NOT the Graph Security
API's security/alerts_v2 endpoint that CloudSecurityEventCollector already
pulls — they are genuinely different data sources that happen to surface
related signals:

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

  - /api/incidents (MDE) — Groups correlated alerts into named incidents
    with their own severity, status, investigation state, and timeline.
    This is the view an SOC analyst uses to track an attack end-to-end:
    the incident shows WHAT happened (categories), HOW it was blocked
    (determination), and WHEN (timeline from first alert to resolution).
    Shows the "incident handling" lifecycle assessors look for in
    IR.L2-3.6.1 and IR.L2-3.6.2.

Both alerts and incidents are collected deliberately — they serve
different assessment objectives at different granularities:
  - Alerts prove individual detection and triage (SI.L2-3.14.3)
  - Incidents prove end-to-end incident handling capability (IR.L2-3.6.1)

CMMC practice mapping:
  SI.L2-3.14.3 — Security Alerts & Advisories (DIRECT): MDE alerts
    with investigation/resolution lifecycle prove "monitor alerts AND
    take action in response" — both halves of the practice.
  SI.L2-3.14.6 — Monitor Communications for Attacks (SUPPORTING): MDE
    detects network-level attack patterns (C2 beaconing, lateral
    movement, exploitation) — partial evidence toward the practice's
    broader "monitor inbound and outbound communications" scope.
  IR.L2-3.6.1 — Incident Handling (DIRECT via incidents): the incident
    lifecycle (Active → Resolved, with classification, determination,
    and correlated alert chain) is direct evidence of incident handling.
  IR.L2-3.6.2 — Incident Reporting (SUPPORTING via incidents): incident
    records with timestamps, severity, and categories serve as evidence
    that incidents ARE being tracked and could be reported, though the
    practice also requires reporting procedures.
  SI.L2-3.14.7 — Identify Unauthorized Use (SUPPORTING): behavioral
    alerts (anomalous process execution, credential abuse, suspicious
    sign-in activity) serve as evidence that unauthorized use IS being
    identified, though the practice also expects a definition of what
    constitutes authorized vs. unauthorized use.

Key alert fields pulled:
  id, title, severity, status, classification, determination,
  investigationState, assignedTo, resolvedTime, firstEventTime,
  lastEventTime, machineId, computerDnsName, category, description,
  detectionSource

Key incident fields pulled:
  incidentId, incidentName, severity, status, classification,
  determination, assignedTo, createdTime, lastUpdateTime, alerts (count
  and service/detection sources derived from the embedded alert array),
  tags

WindowsDefenderATP application permissions required:
  Alert.Read.All for /api/alerts
  Incident.Read.All for /api/incidents

HONEST CONFIDENCE NOTE: /api/alerts is a long-stable, well-documented
MDE API endpoint — materially higher confidence than newer MDE endpoints
(configuration assessment, baseline). /api/incidents is also well-
documented and stable (GA since ~2021), though slightly newer than
/api/alerts. The field names read here are documented in Microsoft's
public MDE API reference. However, the exact $filter syntax MDE accepts
(if any) on these endpoints is not independently confirmed — this
collector uses $filter with alertCreationTime / createdTime as the date
fields (the documented field names), but if that fails, the fallback is
to fetch without a filter and client-side date-filter instead (same
defensive pattern used for sanitization events in cloud_event_collector).
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
    """Collects Microsoft Defender for Endpoint alerts AND incidents with
    full investigation/resolution lifecycle via the MDE API."""

    def __init__(self, mde: MdeClient, lookback_hours: int = 168,
                 max_alerts: int = 2000, max_incidents: int = 500):
        self.mde = mde
        self.lookback_hours = lookback_hours
        self.max_alerts = max_alerts
        self.max_incidents = max_incidents

    def collect(self) -> List[SecurityEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: List[SecurityEvent] = []

        # -- Alerts --
        try:
            events = self._collect_alerts(cutoff_iso)
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("MDE alert collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("MDE alert collection failed: %s", e)

        # -- Incidents --
        try:
            events += self._collect_incidents(cutoff_iso)
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("MDE incident collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("MDE incident collection failed: %s", e)

        logger.info("MDE alert/incident collection complete: %d event(s)", len(events))
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

    # -- Incident collection ------------------------------------------------

    def _collect_incidents(self, cutoff_iso: str) -> List[SecurityEvent]:
        """Pull MDE incidents from /api/incidents with the same defensive
        server-side-filter-then-fallback pattern as alerts.

        The MDE Incident resource uses ``createdTime`` as its creation
        timestamp (documented in the MDE API reference). Each incident
        embeds an ``alerts`` array with the correlated alert objects —
        we pull summary metadata from those (count, service sources,
        detection sources, categories) rather than re-fetching them
        individually, since _collect_alerts already got the full alert
        detail separately.

        Required permission: WindowsDefenderATP -> Incident.Read.All
        """
        out: List[SecurityEvent] = []

        try:
            params = {"$filter": f"createdTime ge {cutoff_iso}", "$top": "5000"}
            for record in self.mde.get_all("api/incidents", params=params):
                out.append(self._map_incident(record))
                if len(out) >= self.max_incidents:
                    logger.warning("  MDE incident cap (%d) reached — more may exist", self.max_incidents)
                    break
        except Exception as filter_err:
            logger.warning(
                "MDE /api/incidents $filter failed (%s) — falling back to unfiltered "
                "fetch with client-side date filtering", filter_err,
            )
            out.clear()
            for record in self.mde.get_all("api/incidents"):
                created = record.get("createdTime") or ""
                if created < cutoff_iso:
                    continue
                out.append(self._map_incident(record))
                if len(out) >= self.max_incidents:
                    logger.warning("  MDE incident cap (%d) reached — more may exist", self.max_incidents)
                    break

        logger.info("  MDE incidents: %d", len(out))
        return out

    @staticmethod
    def _map_incident(record: dict) -> SecurityEvent:
        """Map an MDE Incident resource to a SecurityEvent.

        Key differences from an alert:
          - source is "MDE Incidents" (distinct from alert source, so the
            report can separate them into different display sections)
          - event_data includes incident-specific fields: incident_id,
            incident_name, alert_count, active_alert_count, categories,
            service_sources, detection_sources
          - The embedded ``alerts`` array is summarized (count, sources,
            categories) rather than stored in full — the individual alert
            detail is already captured by _collect_alerts
        """
        severity = record.get("severity") or "Informational"
        level = _SEVERITY_TO_LEVEL.get(severity, "Information")

        incident_name = record.get("incidentName") or "MDE Incident"
        incident_id = record.get("incidentId") or record.get("incidentUri") or ""
        status = record.get("status") or "Unknown"
        classification = record.get("classification") or ""
        determination = record.get("determination") or ""
        assigned_to = record.get("assignedTo") or ""

        # Summarize embedded alerts array
        embedded_alerts = record.get("alerts") or []
        alert_count = len(embedded_alerts)
        active_alerts = sum(1 for a in embedded_alerts if (a.get("status") or "").lower() != "resolved")

        # Collect unique categories, service sources, and detection sources
        categories = sorted({a.get("category") or "Unknown" for a in embedded_alerts if a.get("category")})
        service_sources = sorted({a.get("serviceSource") or "" for a in embedded_alerts if a.get("serviceSource")})
        detection_sources = sorted({a.get("detectionSource") or "" for a in embedded_alerts if a.get("detectionSource")})

        # Collect unique impacted devices from embedded alerts
        impacted_devices = sorted({
            a.get("computerDnsName") or a.get("deviceDnsName") or ""
            for a in embedded_alerts
            if a.get("computerDnsName") or a.get("deviceDnsName")
        })

        # Build message
        message_parts = [f"[MDE Incident] {incident_name} — Status: {status}"]
        if classification:
            message_parts.append(f"Classification: {classification}")
        if determination:
            message_parts.append(f"Determination: {determination}")
        if categories:
            message_parts.append(f"Categories: {', '.join(categories)}")
        message_parts.append(f"Alerts: {active_alerts} active / {alert_count} total")
        if assigned_to:
            message_parts.append(f"Assigned to: {assigned_to}")
        message = " | ".join(message_parts)

        # Use the first impacted device as the "computer" field, or N/A
        computer = impacted_devices[0] if impacted_devices else "N/A"

        return SecurityEvent(
            event_id=0,
            source="MDE Incidents",
            timestamp=record.get("createdTime") or record.get("lastUpdateTime") or "",
            message=message,
            level=level,
            computer=computer,
            user=assigned_to or None,
            event_data={
                "incident_id": incident_id,
                "incident_name": incident_name,
                "severity": severity,
                "status": status,
                "classification": classification,
                "determination": determination,
                "assigned_to": assigned_to,
                "created_time": record.get("createdTime"),
                "last_update_time": record.get("lastUpdateTime"),
                "alert_count": alert_count,
                "active_alert_count": active_alerts,
                "categories": categories,
                "service_sources": service_sources,
                "detection_sources": detection_sources,
                "impacted_devices": impacted_devices,
                "tags": record.get("tags") or [],
            },
        )

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
