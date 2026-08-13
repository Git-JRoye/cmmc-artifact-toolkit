"""Cloud security event collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``EventLogCollector``. Pulls two
Entra log sources and maps both into the existing ``SecurityEvent`` model so
the current scorer (event_logging dimension) and MSP report work unchanged:

  - Sign-in logs (auditLogs/signIns) — authentication attempts, risk level,
    conditional access outcome
  - Directory audit logs (auditLogs/directoryAudits) — administrative and
    configuration-change activity (role assignments, policy changes, etc.)

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

Volume is bounded the same way the on-prem collector bounds it (lookback
window + max event cap), both because sign-in logs can be very large in an
active tenant and to keep this predictable rather than accidentally pulling
a tenant's entire retained audit history on every run.

HONEST CONFIDENCE NOTE: both endpoints are real, documented v1.0 Graph
endpoints, but sign-in log retention varies by Entra ID license tier (as
little as 7 days on some tiers) — an empty or short result set may reflect a
genuine retention limit, not a collection failure. This has not yet been
pilot-tested against a live tenant with real sign-in volume.

Graph application permission required: AuditLog.Read.All (already required
for the Entra identity collector's stale-account detection — no new
permission needed for this collector specifically).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from ..base import CollectorBase
from ...models.artifacts import SecurityEvent
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)

_RISKY_LEVELS = {"high", "medium"}


class CloudSecurityEventCollector(CollectorBase):
    """Collects Entra sign-in and directory audit log events via Microsoft Graph."""

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
