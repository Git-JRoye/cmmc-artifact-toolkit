"""Windows endpoint security posture collector.

Drop-in replacement for the original stub. Runs a PowerShell collection script
and maps its JSON output into typed ``Endpoint`` artifacts. Preserves the
original ``collect() -> List[Endpoint]`` contract, so the gatherer needs no
other changes.

Architecture:
    Python orchestrates; PowerShell collects. ``collect()`` runs the script on
    the local machine. ``collect_remote()`` runs the same script on a remote
    host via WinRM (``Invoke-Command``) — the seam is in place; wire in your
    credential source before using it in production.

Fallback:
    Pass ``demo=True`` (or set ``CMMC_DEMO=1``) to return canned data so the
    pipeline can be exercised without a live Windows target.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Optional

from ..base import CollectorBase
from ...models.artifacts import Endpoint

logger = logging.getLogger(__name__)

# collect_endpoint.ps1 ships alongside this module.
_PS_SCRIPT = Path(__file__).with_name("collect_endpoint.ps1")


class EndpointCollector(CollectorBase):
    """Collects Windows endpoint security data (OS, patches, firewall, AV)."""

    def __init__(self, demo: Optional[bool] = None, ps_timeout: int = 120):
        # Explicit arg wins; otherwise honor the CMMC_DEMO env flag.
        self.demo = bool(int(os.environ.get("CMMC_DEMO", "0"))) if demo is None else demo
        self.ps_timeout = ps_timeout

    # -- public API -------------------------------------------------------

    def collect(self) -> List[Endpoint]:
        """Return endpoint posture for the local machine."""
        if self.demo:
            logger.info("EndpointCollector running in DEMO mode")
            return [self._demo_endpoint()]

        logger.info("Collecting local endpoint data via PowerShell...")
        raw = self._run_powershell(str(_PS_SCRIPT))
        if raw is None:
            logger.error("Endpoint collection produced no output")
            return []

        endpoint = self._parse(raw)
        if endpoint is None:
            return []
        logger.info("Endpoint collection complete: %s", endpoint.hostname)
        return [endpoint]

    def collect_remote(self, hostname: str) -> Optional[Endpoint]:
        """Collect from a remote host via WinRM. Returns None on failure.

        Wire in your credential source (a PSCredential, or a vault lookup keyed
        by tenant) where indicated. Kept explicit rather than implicit so remote
        collection never silently runs with ambient credentials.
        """
        logger.info("Remote endpoint collection: %s", hostname)
        script_body = _PS_SCRIPT.read_text(encoding="utf-8")
        # Invoke-Command streams the script's JSON back over WinRM.
        remote = (
            f"$s = {{ {script_body} }}; "
            f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock $s"
            # TODO: append -Credential $cred  (resolve per-tenant, never hardcode)
        )
        raw = self._run_powershell(remote, from_string=True)
        return self._parse(raw) if raw else None

    # -- internals --------------------------------------------------------

    def _run_powershell(self, script: str, from_string: bool = False) -> Optional[str]:
        """Execute PowerShell and return stdout, or None on error/timeout."""
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
        cmd += ["-Command", script] if from_string else ["-File", script]
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

    def _parse(self, raw: str) -> Optional[Endpoint]:
        """Map the script's JSON object into an Endpoint, or None if unparseable."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Could not parse endpoint JSON: %s", e)
            return None

        errs = (data.get("metadata") or {}).get("collection_errors") or []
        if errs:
            logger.warning("Endpoint %s reported %d section error(s): %s",
                           data.get("hostname"), len(errs), "; ".join(errs))
        return Endpoint(
            hostname=data.get("hostname") or "UNKNOWN",
            ip_address=data.get("ip_address") or "",
            os_version=data.get("os_version") or "Unknown",
            installed_updates=data.get("installed_updates") or [],
            security_products=data.get("security_products") or [],
            firewall_status=data.get("firewall_status"),
            antivirus_status=data.get("antivirus_status"),
            metadata=data.get("metadata") or {},
        )

    @staticmethod
    def _demo_endpoint() -> Endpoint:
        return Endpoint(
            hostname="WORKSTATION-001",
            ip_address="192.168.1.100",
            os_version="Windows 10 Enterprise (Build 19045)",
            installed_updates=["KB5001640", "KB5001631"],
            security_products=["Windows Defender"],
            firewall_status="Enabled",
            antivirus_status="Active",
            metadata={
                "demo": True,
                "installed_software": [
                    {"name": "Google Chrome", "version": "126.0.0.0", "publisher": "Google LLC"},
                    {"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"},
                ],
            },
        )
