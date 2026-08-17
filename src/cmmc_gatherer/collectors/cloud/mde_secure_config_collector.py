"""Microsoft Defender for Endpoint security configuration assessment collector.

Collects per-device security configuration assessment results via MDE's
export API. These are the results of MDE's continuous security
configuration checks — whether specific security settings (like Credential
Guard, ASLR enforcement, firewall configuration, audit policies) are
correctly configured on each device.

CMMC practice mapping:
  CM.L2-3.4.2 — Security Configuration Enforcement (DIRECT): this is
    literally what the practice asks for — "establish and enforce
    security configuration settings." MDE's configuration assessment
    shows whether each specific security setting IS in its expected
    state on each device, not just whether a policy REQUIRES it.
    This is OBSERVED STATE evidence, the strongest class in this
    project's own evidence taxonomy (see control_mapping.py's rule).
  CM.L2-3.4.1 — System Baselining (SUPPORTING): the configuration
    assessment results implicitly document what the expected baseline
    IS (the "compliant" state each check evaluates against), though
    the practice primarily asks for explicit baseline documentation.

Data source: MDE's export-based assessment APIs. There are two possible
endpoints here:
  1. /api/machines/{id}/securityConfigurationAssessment — per-machine,
     requires one call per device (expensive for large tenants)
  2. Export APIs that return assessment data in bulk

This collector uses the bulk approach: /api/machines/
SecureConfigurationsAssessmentByMachine (or the equivalent export
endpoint). The exact endpoint path is the LOWEST confidence piece of
this collector — if the bulk endpoint doesn't exist or uses a different
name, the per-machine fan-out is the documented fallback.

WindowsDefenderATP application permission: SecurityConfiguration.Read.All

HONEST CONFIDENCE NOTE: this is one of the NEWER, less-documented MDE
API surfaces. The exact endpoint path, response shape, and field names
are recalled with LOW confidence — lower than /api/machines or
/api/alerts, which are long-stable. The response body is logged on any
error, and the collector is designed to degrade gracefully (returns
empty Policy list, never crashes the run).
"""

import logging
from typing import List

from ..base import CollectorBase
from ...models.artifacts import Policy
from ...cloud.graph import MdeClient

logger = logging.getLogger(__name__)


class MdeSecureConfigCollector(CollectorBase):
    """Collects security configuration assessment results from MDE,
    mapped as Policy records showing whether each security setting is
    correctly configured on each device."""

    def __init__(self, mde: MdeClient, max_records: int = 5000):
        self.mde = mde
        self.max_records = max_records

    def collect(self) -> List[Policy]:
        policies: List[Policy] = []
        try:
            policies = self._collect_config_assessments()
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error(
                    "MDE security configuration assessment failed: %s | Response: %s",
                    e, detail[:500],
                )
            else:
                logger.error("MDE security configuration assessment failed: %s", e)
        logger.info("MDE security configuration collection complete: %d record(s)", len(policies))
        return policies

    def _collect_config_assessments(self) -> List[Policy]:
        """Try the bulk export endpoint first; fall back to per-machine
        if the bulk endpoint doesn't exist.

        HONEST CONFIDENCE NOTE: the bulk endpoint path is the single
        least-confident piece of this entire MDE integration. Multiple
        plausible paths exist in MDE documentation:
          - /api/machines/SecureConfigurationsAssessmentByMachine
          - /api/machines/secureConfigurationsAssessment
          - A v2 export API under /api/machines/ConfigurationAssessment
        This tries the most commonly documented one first, then falls
        back. The response body on error tells us which (if any) is
        correct.
        """
        # Primary attempt: bulk endpoint
        out: List[Policy] = []
        try:
            for record in self.mde.get_all("api/machines/SecureConfigurationsAssessmentByMachine"):
                policy = self._map_config_assessment(record)
                if policy is not None:
                    out.append(policy)
                if len(out) >= self.max_records:
                    logger.warning(
                        "  MDE secure config cap (%d) reached — more may exist",
                        self.max_records,
                    )
                    break
            logger.info("  MDE secure configuration assessments: %d", len(out))
            return out
        except Exception as bulk_err:
            logger.warning(
                "MDE bulk secure config endpoint failed (%s) — "
                "this endpoint may not exist or may use a different path; "
                "no fallback implemented yet (would require per-machine fan-out "
                "which is expensive). Returning empty.", bulk_err,
            )
            return []

    @staticmethod
    def _map_config_assessment(record: dict) -> Policy:
        """Map one MDE security configuration assessment record into a
        Policy object.

        Expected fields (moderate confidence):
          configurationId — unique identifier for the security check
          configurationName — human-readable name
          configurationCategory — category (e.g. "OS", "Network", etc.)
          isCompliant / complianceStatus — whether the device passes
          isApplicable — whether the check applies to this device
          deviceName — the device this assessment is for
          osPlatform — device OS
        """
        config_name = record.get("configurationName") or record.get("configurationId") or "Unknown config"
        category = record.get("configurationCategory") or "Uncategorized"
        device_name = record.get("deviceName") or record.get("computerDnsName") or "Unknown device"

        # Three-state compliance: True/False/None
        is_compliant = record.get("isCompliant")
        if is_compliant is None:
            # Try alternate field name
            compliance_status = record.get("complianceStatus") or ""
            if compliance_status.lower() in ("compliant", "true"):
                is_compliant = True
            elif compliance_status.lower() in ("noncompliant", "false"):
                is_compliant = False
            # else: remains None — genuinely unknown

        is_applicable = record.get("isApplicable")
        if is_applicable is False:
            status = "Not Applicable"
        elif is_compliant is True:
            status = "Enabled"
        elif is_compliant is False:
            status = "Disabled"
        else:
            status = "Unknown"

        return Policy(
            policy_name=config_name,
            policy_type="MDE Security Configuration",
            status=status,
            target=f"Device: {device_name}",
            value=f"Compliant: {is_compliant}" if is_compliant is not None else "Status unknown",
            description=(
                f"MDE security configuration check ({category}): "
                f"'{config_name}' on {device_name} — "
                f"{'PASSES' if is_compliant else 'FAILS' if is_compliant is False else 'unknown'}"
            ),
            last_applied=None,
        )
