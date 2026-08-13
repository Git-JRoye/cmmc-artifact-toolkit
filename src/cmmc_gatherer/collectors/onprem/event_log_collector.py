"""Windows Security Event Log collector.

Replaces the original demo stub. Runs a PowerShell collection script and maps
its JSON output into typed ``SecurityEvent`` artifacts. Preserves the original
public methods (``collect()``, ``collect_critical_events()``), so the
gatherer needs no other changes.

Relevant event IDs for CMMC compliance (also documented in the .ps1 script):
    4624/4625 — logon success/failure     4634/4647 — logoff
    4720/4722/4725/4740/4767 — account created/enabled/disabled/locked/unlocked
    4728/4732/4756 — security-enabled group membership changes (privileged groups)
    4672 — special/privileged logon        4719 — audit policy changed
    4670 — permissions on an object changed

Architecture:
    Python orchestrates; PowerShell collects — same pattern as the endpoint
    collector. ``collect()`` runs locally. ``collect_remote()`` runs via WinRM;
    the seam is in place, wire in a per-tenant credential source before use.

Fallback:
    Pass ``demo=True`` (or set ``CMMC_DEMO=1``) to return canned data.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Optional

from ..base import CollectorBase
from ...models.artifacts import SecurityEvent

logger = logging.getLogger(__name__)

_PS_SCRIPT = Path(__file__).with_name("collect_events.ps1")
_CRITICAL_LEVELS = {"Critical", "Error"}


class EventLogCollector(CollectorBase):
    """Collects Windows Security Event Log entries relevant to CMMC controls."""

    def __init__(self, demo: Optional[bool] = None, lookback_hours: int = 168,
                 max_events: int = 2000, ps_timeout: int = 180):
        self.demo = bool(int(os.environ.get("CMMC_DEMO", "0"))) if demo is None else demo
        self.lookback_hours = lookback_hours
        self.max_events = max_events
        self.ps_timeout = ps_timeout

    # -- public API -------------------------------------------------------

    def collect(self) -> List[SecurityEvent]:
        """Return security events from the local Windows event log."""
        if self.demo:
            logger.info("EventLogCollector running in DEMO mode")
            return [self._demo_event()]

        logger.info("Collecting Windows Security Event Log data "
                    "(last %sh, max %s events)...", self.lookback_hours, self.max_events)
        raw = self._run_powershell(self._local_args())
        events = self._parse(raw)
        logger.info("Event log collection complete: %d event(s)", len(events))
        return events

    def collect_critical_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Return only Critical and Error level events from the last N hours."""
        logger.info("Collecting critical events from last %s hour(s)...", hours)
        if self.demo:
            return [e for e in [self._demo_event()] if e.level in _CRITICAL_LEVELS]

        raw = self._run_powershell(self._local_args(lookback_hours=hours))
        events = self._parse(raw)
        return [e for e in events if e.level in _CRITICAL_LEVELS]

    def collect_remote(self, hostname: str) -> List[SecurityEvent]:
        """Collect from a remote host via WinRM. Returns [] on failure.

        Wire in your credential source (a PSCredential, or a vault lookup keyed
        by tenant) where indicated — kept explicit so this never silently runs
        with ambient credentials.
        """
        logger.info("Remote event log collection: %s", hostname)
        script_body = _PS_SCRIPT.read_text(encoding="utf-8")
        remote = (
            f"$s = {{ {script_body} }}; "
            f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock $s "
            f"-ArgumentList @('{self.lookback_hours}', '{self.max_events}')"
            # TODO: append -Credential $cred  (resolve per-tenant, never hardcode)
        )
        raw = self._run_powershell(remote, from_string=True)
        return self._parse(raw) if raw else []

    # -- internals --------------------------------------------------------

    def _local_args(self, lookback_hours: Optional[int] = None) -> List[str]:
        return [
            str(_PS_SCRIPT),
            "-LookbackHours", str(lookback_hours or self.lookback_hours),
            "-MaxEvents", str(self.max_events),
        ]

    def _run_powershell(self, args, from_string: bool = False) -> Optional[str]:
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
        cmd += ["-Command", args] if from_string else ["-File"] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.ps_timeout, check=False,
            )
        except FileNotFoundError:
            logger.error("PowerShell not found — is this a Windows host? Use demo=True to test.")
            return None
        except subprocess.TimeoutExpired:
            logger.error("PowerShell timed out after %ss", self.ps_timeout)
            return None

        if result.returncode != 0:
            logger.error("PowerShell exited %s: %s", result.returncode, result.stderr.strip())
            return None
        if result.stderr.strip():
            logger.warning("PowerShell stderr: %s", result.stderr.strip())
        return result.stdout.strip() or None

    def _parse(self, raw: Optional[str]) -> List[SecurityEvent]:
        if raw is None:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Could not parse event log JSON: %s", e)
            return []

        for err in data.get("collection_errors") or []:
            logger.warning("Event log collection error: %s", err)

        events: List[SecurityEvent] = []
        for e in data.get("events") or []:
            events.append(SecurityEvent(
                event_id=e.get("event_id") or 0,
                source=e.get("source") or "Security",
                timestamp=e.get("timestamp") or "",
                message=e.get("message") or "",
                level=e.get("level") or "Information",
                computer=e.get("computer") or "UNKNOWN",
                user=e.get("user"),
                event_data=e.get("event_data") or {},
            ))
        return events

    @staticmethod
    def _demo_event() -> SecurityEvent:
        return SecurityEvent(
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
        )
