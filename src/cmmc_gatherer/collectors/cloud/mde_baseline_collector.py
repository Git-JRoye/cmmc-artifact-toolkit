"""Microsoft Defender for Endpoint security baseline compliance collector.

Collects per-device security baseline assessment results from MDE. Security
baselines are curated sets of security configuration recommendations (e.g.
Microsoft's own security baseline for Windows 10/11) that are evaluated
against each onboarded device. Where MdeSecureConfigCollector reports on
INDIVIDUAL security settings, this collector reports against BASELINE
PROFILES — a higher-level view of whether a device conforms to a named,
documented security standard.

CMMC practice mapping:
  CM.L2-3.4.1 — System Baselining (DIRECT): this is literally what the
    practice asks for — "establish and maintain baseline configurations."
    MDE's security baselines ARE established configuration baselines
    evaluated against real devices. The assessment results prove both
    that a baseline EXISTS and that it's being actively MEASURED against
    real systems — both halves of the practice's assessment objectives.
  CM.L2-3.4.2 — Security Configuration Enforcement (SUPPORTING): baseline
    compliance results show whether configurations ARE enforced across
    devices, though the practice also asks for the enforcement mechanism
    itself (GPO, MDM, etc.), which this data alone doesn't fully cover.

Key fields pulled:
  deviceId / machineId — device identifier
  deviceName — device hostname
  profileName / baselineName — which baseline is being evaluated
  complianceStatus / isCompliant — whether the device passes
  configurationId — individual setting within the baseline (if per-setting)
  settingName — human-readable setting name

WindowsDefenderATP application permission:
  SecurityBaselinesAssessment.Read.All

HONEST CONFIDENCE NOTE: this is the LOWEST confidence MDE endpoint in
this entire integration. SecurityBaselinesAssessment.Read.All is a
documented permission, but the exact API endpoint path it unlocks is not
confidently known. Plausible paths:
  - /api/machines/BaselineComplianceAssessmentByMachine
  - /api/machines/securityBaselinesAssessment
  - A sub-path under /api/configuration or /api/baselineProfiles

This collector tries the most plausible path and degrades gracefully to
an empty list with a logged warning if it doesn't work. The response
body is always logged on error so the real pilot reveals the correct path.
"""

import logging
from typing import List, Optional

from ..base import CollectorBase
from ...models.artifacts import Policy
from ...cloud.graph import MdeClient

logger = logging.getLogger(__name__)


class MdeBaselineCollector(CollectorBase):
    """Collects security baseline compliance assessment results from MDE."""

    def __init__(self, mde: MdeClient, max_records: int = 5000):
        self.mde = mde
        self.max_records = max_records

    def collect(self) -> List[Policy]:
        policies: List[Policy] = []
        try:
            policies = self._collect_baseline_assessments()
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error(
                    "MDE security baseline assessment failed: %s | Response: %s",
                    e, detail[:500],
                )
            else:
                logger.error("MDE security baseline assessment failed: %s", e)
        logger.info("MDE security baseline collection complete: %d record(s)", len(policies))
        return policies

    def _collect_baseline_assessments(self) -> List[Policy]:
        """Try known endpoint paths in order. Each MDE export-style
        assessment API has slight naming variations; we try the most
        commonly documented path first.

        HONEST CONFIDENCE NOTE: the exact path is the primary
        uncertainty here — everything else (response shape, field names)
        follows standard MDE export-assessment patterns. If the first
        path fails, we try one alternate before giving up.
        """
        candidate_paths = [
            "api/machines/BaselineComplianceAssessmentByMachine",
            "api/machines/securityBaselinesAssessment",
        ]

        for path in candidate_paths:
            try:
                out = self._try_path(path)
                logger.info("  MDE security baseline assessments via %s: %d", path, len(out))
                return out
            except Exception as e:
                detail = getattr(getattr(e, "response", None), "text", None)
                if detail:
                    logger.warning(
                        "MDE baseline path '%s' failed: %s | Response: %s",
                        path, e, detail[:500],
                    )
                else:
                    logger.warning("MDE baseline path '%s' failed: %s", path, e)

        logger.warning(
            "All MDE security baseline endpoint paths failed — this permission "
            "(SecurityBaselinesAssessment.Read.All) may use an endpoint path not "
            "yet known to this collector. Returning empty."
        )
        return []

    def _try_path(self, path: str) -> List[Policy]:
        out: List[Policy] = []
        for record in self.mde.get_all(path):
            policy = self._map_baseline_assessment(record)
            if policy is not None:
                out.append(policy)
            if len(out) >= self.max_records:
                logger.warning(
                    "  MDE baseline cap (%d) reached — more may exist",
                    self.max_records,
                )
                break
        return out

    @staticmethod
    def _map_baseline_assessment(record: dict) -> Optional[Policy]:
        """Map one MDE security baseline assessment record into a Policy.

        Expected response shape (moderate-to-low confidence):
          profileName / baselineName — the named baseline being evaluated
          configurationId / settingId — specific setting within the baseline
          settingName / configurationName — human-readable setting name
          isCompliant / complianceStatus — pass/fail for this setting
          deviceName / computerDnsName — the device
          deviceId / machineId — device identifier
        """
        # Baseline / profile name — try multiple field name hypotheses
        baseline_name = (
            record.get("profileName")
            or record.get("baselineName")
            or record.get("baselineProfileName")
            or "Unknown Baseline"
        )

        setting_name = (
            record.get("settingName")
            or record.get("configurationName")
            or record.get("configurationId")
            or "Unknown Setting"
        )

        device_name = (
            record.get("deviceName")
            or record.get("computerDnsName")
            or "Unknown device"
        )

        # Three-state compliance
        is_compliant = record.get("isCompliant")
        if is_compliant is None:
            cs = (record.get("complianceStatus") or "").lower()
            if cs in ("compliant", "true"):
                is_compliant = True
            elif cs in ("noncompliant", "false", "notcompliant"):
                is_compliant = False

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
            policy_name=f"{baseline_name}: {setting_name}",
            policy_type="MDE Security Baseline",
            status=status,
            target=f"Device: {device_name}",
            value=f"Compliant: {is_compliant}" if is_compliant is not None else "Status unknown",
            description=(
                f"MDE security baseline '{baseline_name}' — setting '{setting_name}' "
                f"on {device_name}: "
                f"{'PASSES' if is_compliant else 'FAILS' if is_compliant is False else 'unknown'}"
            ),
            last_applied=None,
        )
