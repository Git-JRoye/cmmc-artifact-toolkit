"""Windows security policy collector.

Replaces the original demo stub. Runs a PowerShell collection script and maps
its JSON output into typed ``Policy`` artifacts. Preserves the original
``collect() -> List[Policy]`` contract.

Covers password/lockout policy, UAC settings, CMMC-relevant audit policy
categories, and a name list of applied Group Policy Objects — see
collect_policy.ps1's header for exactly what's included and the one
documented gap (applied-GPO names only, not a full RSOP parse).

Architecture: same Python-orchestrates/PowerShell-collects pattern as the
endpoint and event-log collectors, including a WinRM remote seam.

Fallback: pass ``demo=True`` (or set ``CMMC_DEMO=1``) for canned data.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Optional

from ..base import CollectorBase
from ...models.artifacts import Policy

logger = logging.getLogger(__name__)

_PS_SCRIPT = Path(__file__).with_name("collect_policy.ps1")


class PolicyCollector(CollectorBase):
    """Collects Windows security policy configuration (password, UAC, audit, GPO)."""

    def __init__(self, demo: Optional[bool] = None, ps_timeout: int = 120):
        self.demo = bool(int(os.environ.get("CMMC_DEMO", "0"))) if demo is None else demo
        self.ps_timeout = ps_timeout

    # -- public API -------------------------------------------------------

    def collect(self) -> List[Policy]:
        """Return policy configuration for the local machine."""
        if self.demo:
            logger.info("PolicyCollector running in DEMO mode")
            return self._demo_policies()

        logger.info("Collecting Windows security policy data...")
        raw = self._run_powershell(str(_PS_SCRIPT))
        policies = self._parse(raw)
        logger.info("Policy collection complete: %d record(s)", len(policies))
        return policies

    def collect_remote(self, hostname: str) -> List[Policy]:
        """Collect from a remote host via WinRM. Returns [] on failure.

        Wire in your credential source (a PSCredential, or a vault lookup keyed
        by tenant) where indicated — kept explicit so this never silently runs
        with ambient credentials.
        """
        logger.info("Remote policy collection: %s", hostname)
        script_body = _PS_SCRIPT.read_text(encoding="utf-8")
        remote = (
            f"$s = {{ {script_body} }}; "
            f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock $s"
            # TODO: append -Credential $cred  (resolve per-tenant, never hardcode)
        )
        raw = self._run_powershell(remote, from_string=True)
        return self._parse(raw) if raw else []

    # -- internals --------------------------------------------------------

    def _run_powershell(self, script: str, from_string: bool = False) -> Optional[str]:
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

    def _parse(self, raw: Optional[str]) -> List[Policy]:
        if raw is None:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Could not parse policy JSON: %s", e)
            return []

        for err in data.get("collection_errors") or []:
            logger.warning("Policy collection error: %s", err)

        policies: List[Policy] = []
        for p in data.get("policies") or []:
            policies.append(Policy(
                policy_name=p.get("policy_name") or "Unknown",
                policy_type=p.get("policy_type") or "Local Policy",
                status=p.get("status") or "Not Configured",
                target=p.get("target") or "Computer",
                value=p.get("value"),
                description=p.get("description"),
                last_applied=p.get("last_applied"),
            ))
        return policies

    @staticmethod
    def _demo_policies() -> List[Policy]:
        return [
            Policy(
                policy_name="MinimumPasswordLength", policy_type="Local Security Policy",
                status="Configured", target="Computer", value="14",
                description="Minimum password length (characters)", last_applied=None,
            ),
            Policy(
                policy_name="EnableLUA", policy_type="UAC (Local Policy)",
                status="Enabled", target="Computer", value="1",
                description="User Account Control (UAC) enabled", last_applied=None,
            ),
        ]
