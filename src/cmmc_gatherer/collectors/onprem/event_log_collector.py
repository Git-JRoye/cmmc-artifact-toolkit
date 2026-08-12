"""Windows Security Event Log collector."""

import logging
from typing import List
from ..base import CollectorBase
from ...models.artifacts import SecurityEvent

logger = logging.getLogger(__name__)


class EventLogCollector(CollectorBase):
    """Collects Windows Security Event Log entries.

    Relevant event IDs for CMMC compliance:
      4624 — successful logon
      4625 — failed logon (repeated = brute-force indicator)
      4720 — user account created
      4728/4732/4756 — security group membership changed

    In production queries the Security log via the Windows Event Log API.
    Currently returns demo data.
    """

    def collect(self) -> List[SecurityEvent]:
        """Return security events from the Windows event log."""
        logger.info("Collecting Windows Security Event Log data...")
        events: List[SecurityEvent] = []
        try:
            events.append(SecurityEvent(
                event_id=4624,
                source="Security",
                timestamp="2026-05-14T10:30:00Z",
                message="An account was successfully logged on",
                level="Information",
                computer="WORKSTATION-001",
                user="DOMAIN\\administrator",
                event_data={
                    "LogonType": "3",
                    "LogonProcessName": "NtLmSsp",
                    "AuthenticationPackageName": "NTLM",
                    "SourceIPAddress": "192.168.1.50",
                },
            ))
            logger.info(f"Event log collection complete: {len(events)} event(s)")
        except Exception as e:
            logger.error(f"Failed to collect event logs: {e}")
        return events

    def collect_critical_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Return only Critical and Error level events from the last N hours."""
        logger.info(f"Collecting critical events from last {hours} hour(s)...")
        # TODO: Implement critical event filtering
        return []
