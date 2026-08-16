"""Cloud security event collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``EventLogCollector``. Pulls
three Entra/Graph log sources and maps all into the existing
``SecurityEvent`` model so the current scorer (event_logging dimension)
and MSP report work unchanged:

  - Sign-in logs (auditLogs/signIns) — authentication attempts, risk level,
    conditional access outcome
  - Directory audit logs (auditLogs/directoryAudits) — administrative and
    configuration-change activity (role assignments, policy changes, etc.)
  - Security alerts (security/alerts_v2) — alerts surfaced through the
    unified Microsoft Graph Security API, from whichever security products
    are actually deployed (Defender for Endpoint, Defender for Office 365,
    Defender for Identity, Sentinel if connected) — real detections, not
    just configuration/audit trail.

Level mapping (Critical/Error/Warning/Information) is a judgment call, same
as the on-prem collector's reliance on Windows' own event levels — there is
no equivalent built-in severity for Graph audit data, so this collector
assigns one using the same intent as the compliance scorer's existing
Critical/Error ratio check:
  - A sign-in with a risk level of 'high' or 'medium' during sign-in -> Critical
    (an authenticated session where Entra itself flagged risk is a materially
    different signal than a routine failed password attempt).
  - A failed sign-in (non-zero error code) -> Error.
  - A successful, non-risky sign-in -> Information.
  - A directory audit entry with result == 'failure' -> Error.
  - Any other directory audit entry -> Information.
  - A security alert with severity 'high' -> Critical, 'medium' -> Error,
    'low' -> Warning, 'informational' (or anything else) -> Information —
    reusing Microsoft's own stated severity rather than inventing a new scale.

Volume is bounded the same way the on-prem collector bounds it (lookback
window + max event cap), both because sign-in logs can be very large in an
active tenant and to keep this predictable rather than accidentally pulling
a tenant's entire retained audit history on every run.

HONEST CONFIDENCE NOTE: sign-in and directory audit endpoints are real,
documented v1.0 Graph endpoints, but sign-in log retention varies by Entra
ID license tier (as little as 7 days on some tiers) — an empty or short
result set may reflect a genuine retention limit, not a collection failure.

security/alerts_v2 specifically is LOWER confidence than the other two —
Microsoft has moved this API between versions before (the older
security/alerts was deprecated in favor of alerts_v2), and this is built
against v1.0 with a createdDateTime filter, both recalled rather than
independently verified against current documentation. If this 404s or
400s on a real pilot, check the response body before assuming a logic
error — the same discipline every other new endpoint this session has
needed.

Graph application permission required: AuditLog.Read.All (existing, sign-
in + directory audit logs) and SecurityAlert.Read.All (NEW, for
security/alerts_v2).

PILOT FINDING (real, confirmed): the first version of this docstring named
SecurityEvents.Read.All as the required permission for security/alerts_v2 —
that was wrong. A real 403 against a live tenant gave Graph's own error
text: "Missing application roles. API required roles: SecurityAlert.Read.All,
SecurityAlert.ReadWrite.All, SecurityIncident.Read.All,
SecurityIncident.ReadWrite.All." SecurityAlert.Read.All is the correct,
least-privileged one of those four for a read-only compliance tool. If this
still 403s after adding SecurityAlert.Read.All and granting admin consent,
the real error message will say so explicitly — check it before assuming
another permission is needed.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from ..base import CollectorBase
from ...models.artifacts import SecurityEvent
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)

_RISKY_LEVELS = {"high", "medium"}
_ALERT_SEVERITY_TO_LEVEL = {
    "high": "Critical",
    "medium": "Error",
    "low": "Warning",
    "informational": "Information",
}


class CloudSecurityEventCollector(CollectorBase):
    """Collects Entra sign-in logs, directory audit logs, and Graph
    Security API alerts via Microsoft Graph."""

    def __init__(self, graph: GraphClient, lookback_hours: int = 168, max_events: int = 2000):
        self.graph = graph
        self.lookback_hours = lookback_hours
        self.max_events = max_events

    def collect(self) -> List[SecurityEvent]:
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        events: List[SecurityEvent] = []
        try:
            events += self._collect_signins(cutoff_iso)
        except Exception as e:
            logger.error("Entra sign-in log collection failed: %s", e)
        try:
            events += self._collect_directory_audits(cutoff_iso)
        except Exception as e:
            logger.error("Entra directory audit log collection failed: %s", e)
        try:
            events += self._collect_security_alerts(cutoff_iso)
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Security alerts collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("Security alerts collection failed: %s", e)
        logger.info("Cloud security event collection complete: %d event(s)", len(events))
        return events

    # -- sign-in logs ---------------------------------------------------------

    def _collect_signins(self, cutoff_iso: str) -> List[SecurityEvent]:
        out: List[SecurityEvent] = []
        params = {
            "$filter": f"createdDateTime ge {cutoff_iso}",
            "$top": "999",
        }
        for record in self.graph.get_all("auditLogs/signIns", params=params):
            out.append(self._map_signin(record))
            if len(out) >= self.max_events:
                logger.warning("  Sign-in log cap (%d) reached — more events may exist "
                                "in the lookback window than were collected", self.max_events)
                break
        logger.info("  Sign-in events: %d", len(out))
        return out

    @staticmethod
    def _map_signin(record: dict) -> SecurityEvent:
        status = record.get("status") or {}
        error_code = status.get("errorCode")
        risk_level = (record.get("riskLevelDuringSignIn") or "none").lower()
        failed = bool(error_code)

        if risk_level in _RISKY_LEVELS:
            level = "Critical"
        elif failed:
            level = "Error"
        else:
            level = "Information"

        device = record.get("deviceDetail") or {}
        outcome = "failed" if failed else "succeeded"
        message = (
            f"Sign-in {outcome} for {record.get('userPrincipalName', 'unknown user')} "
            f"to {record.get('appDisplayName', 'unknown app')} from "
            f"{record.get('ipAddress', 'unknown IP')}"
        )
        if failed:
            message += f" (error {error_code}: {status.get('failureReason', 'no reason given')})"

        # Graph's sign-in id is a string GUID-like value; SecurityEvent.event_id
        # is typed int for the on-prem Windows Event ID convention — no
        # equivalent numeric ID exists here, so 0 is used as a sentinel and
        # the real Graph id is preserved in event_data for traceability.
        return SecurityEvent(
            event_id=0,
            source="Entra Sign-In Logs",
            timestamp=record.get("createdDateTime") or "",
            message=message,
            level=level,
            computer=device.get("displayName") or "N/A (cloud sign-in)",
            user=record.get("userPrincipalName"),
            event_data={
                "graph_id": record.get("id"),
                "app_display_name": record.get("appDisplayName"),
                "ip_address": record.get("ipAddress"),
                "error_code": error_code,
                "failure_reason": status.get("failureReason"),
                "risk_level_during_signin": record.get("riskLevelDuringSignIn"),
                "conditional_access_status": record.get("conditionalAccessStatus"),
                "client_app_used": record.get("clientAppUsed"),
            },
        )

    # -- directory audit logs -------------------------------------------------

    def _collect_directory_audits(self, cutoff_iso: str) -> List[SecurityEvent]:
        out: List[SecurityEvent] = []
        params = {
            "$filter": f"activityDateTime ge {cutoff_iso}",
            "$top": "999",
        }
        for record in self.graph.get_all("auditLogs/directoryAudits", params=params):
            out.append(self._map_directory_audit(record))
            if len(out) >= self.max_events:
                logger.warning("  Directory audit log cap (%d) reached — more events may "
                                "exist in the lookback window than were collected", self.max_events)
                break
        logger.info("  Directory audit events: %d", len(out))
        return out

    @staticmethod
    def _map_directory_audit(record: dict) -> SecurityEvent:
        result = (record.get("result") or "").lower()
        level = "Error" if result == "failure" else "Information"
        initiated_by = record.get("initiatedBy") or {}
        initiator = (
            (initiated_by.get("user") or {}).get("userPrincipalName")
            or (initiated_by.get("app") or {}).get("displayName")
            or "unknown"
        )
        targets = record.get("targetResources") or []
        target_names = [t.get("displayName") for t in targets if t.get("displayName")]

        message = f"{record.get('activityDisplayName', 'Directory activity')} by {initiator}"
        if target_names:
            message += f" targeting: {', '.join(target_names)}"

        return SecurityEvent(
            event_id=0,
            source="Entra Directory Audit Logs",
            timestamp=record.get("activityDateTime") or "",
            message=message,
            level=level,
            computer="N/A (cloud audit)",
            user=initiator,
            event_data={
                "graph_id": record.get("id"),
                "category": record.get("category"),
                "activity_display_name": record.get("activityDisplayName"),
                "result": record.get("result"),
                "result_reason": record.get("resultReason"),
                "target_resources": target_names,
            },
        )

    # -- security alerts (Graph Security API) --------------------------------

    def _collect_security_alerts(self, cutoff_iso: str) -> List[SecurityEvent]:
        out: List[SecurityEvent] = []
        params = {
            "$filter": f"createdDateTime ge {cutoff_iso}",
            "$top": "999",
        }
        for record in self.graph.get_all("security/alerts_v2", params=params):
            out.append(self._map_security_alert(record))
            if len(out) >= self.max_events:
                logger.warning("  Security alert cap (%d) reached — more alerts may exist "
                                "in the lookback window than were collected", self.max_events)
                break
        logger.info("  Security alerts: %d", len(out))
        return out

    @staticmethod
    def _map_security_alert(record: dict) -> SecurityEvent:
        severity = (record.get("severity") or "informational").lower()
        level = _ALERT_SEVERITY_TO_LEVEL.get(severity, "Information")

        vendor_info = record.get("vendorInformation") or {}
        provider = vendor_info.get("provider") or "Unknown Provider"
        title = record.get("title") or "Security alert"

        return SecurityEvent(
            event_id=0,
            source="Microsoft Graph Security Alerts",
            timestamp=record.get("createdDateTime") or "",
            message=f"[{provider}] {title}",
            level=level,
            computer="N/A (cloud security alert)",
            user=None,
            event_data={
                "graph_id": record.get("id"),
                "severity": record.get("severity"),
                "status": record.get("status"),
                "category": record.get("category"),
                "provider": provider,
                "classification": record.get("classification"),
                "determination": record.get("determination"),
            },
        )
