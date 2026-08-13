"""Compliance scoring based on collected artifacts.

Scores six dimensions and combines them as a weighted average. This is a
genuine improvement over the original placeholder heuristics (which rewarded
event *volume* and AD object *count* rather than actual security signal), but
it is still NOT a full CMMC/NIST 800-171 practice mapping or SPRS methodology
— that's a separate, larger rework. What changed here:

  - firewall/antivirus/updates now only evaluate on-prem-sourced endpoints
    (identified by firewall_status is not None). Cloud (Intune) endpoints
    deliberately leave those fields null rather than fake them — scoring them
    as failures was actively wrong, not just imprecise.
  - policies now evaluates each entry against a real pass/fail rule keyed to
    what that specific setting means (e.g. ClearTextPassword=Disabled is the
    SECURE state — the opposite of most boolean policies), instead of a blind
    status == "Enabled" check that doesn't match the real collector's output
    shapes ("Configured", "Success and Failure", "Applied", etc.).
  - event_logging now penalizes a high ratio of Critical/Error events instead
    of rewarding raw event count.
  - ad_security now uses the isStale/disabled flags the real AD/Entra
    collectors already produce (an enabled-but-stale account is the actual
    risk signal — disabled accounts and object *count* are not).

Any dimension with no applicable data returns None rather than 0 or 100 (we
don't guess), and the overall score renormalizes weights across only the
dimensions that had data — so a cloud-only tenant with no on-prem endpoints
isn't penalized for a metric that doesn't apply to them.
"""

import logging
from typing import Optional

from ..models.artifacts import ADObject, ArtifactCollection, Policy

logger = logging.getLogger(__name__)


class ComplianceScorer:
    """Calculates a weighted compliance score (0-100) from an ArtifactCollection."""

    SCORE_WEIGHTS = {
        'firewall': 15,
        'antivirus': 15,
        'updates': 15,
        'policies': 20,
        'event_logging': 15,
        'ad_security': 20,
    }

    @classmethod
    def calculate_overall_score(cls, artifacts: ArtifactCollection) -> int:
        """Return a 0-100 compliance score, weighted across applicable dimensions only."""
        results = {
            'firewall': cls._score_firewall(artifacts),
            'antivirus': cls._score_antivirus(artifacts),
            'updates': cls._score_updates(artifacts),
            'policies': cls._score_policies(artifacts),
            'event_logging': cls._score_event_logging(artifacts),
            'ad_security': cls._score_ad_security(artifacts),
        }
        applicable = {k: v for k, v in results.items() if v is not None}
        if not applicable:
            logger.warning("No scoreable dimensions had applicable data — returning 0")
            return 0

        weighted_sum = sum((v / 100) * cls.SCORE_WEIGHTS[k] for k, v in applicable.items())
        weight_total = sum(cls.SCORE_WEIGHTS[k] for k in applicable)
        score = (weighted_sum / weight_total) * 100
        return int(max(0, min(100, score)))

    # -- endpoint dimensions (on-prem only — see module docstring) -----------

    @classmethod
    def _onprem_endpoints(cls, artifacts: ArtifactCollection):
        # firewall_status is only ever set by the on-prem collector; cloud
        # (Intune) endpoints leave it None deliberately. Use it as the signal
        # for "this endpoint has on-prem-style data to score."
        return [ep for ep in artifacts.endpoints if ep.firewall_status is not None]

    @classmethod
    def _score_firewall(cls, artifacts: ArtifactCollection) -> Optional[int]:
        applicable = cls._onprem_endpoints(artifacts)
        if not applicable:
            return None
        points = {'Enabled': 100, 'Partial': 50, 'Disabled': 0}
        total = sum(points.get(ep.firewall_status, 0) for ep in applicable)
        return int(total / len(applicable))

    @classmethod
    def _score_antivirus(cls, artifacts: ArtifactCollection) -> Optional[int]:
        applicable = [ep for ep in artifacts.endpoints if ep.antivirus_status is not None]
        if not applicable:
            return None
        active = sum(1 for ep in applicable if ep.antivirus_status == "Active")
        return int((active / len(applicable)) * 100)

    @classmethod
    def _score_updates(cls, artifacts: ArtifactCollection) -> Optional[int]:
        # NOTE: this only checks whether ANY hotfix history was collected, not
        # whether the endpoint is current against the latest available patches
        # — real recency-based patch scoring needs an external patch-baseline
        # source and is a good candidate for a future enhancement.
        applicable = cls._onprem_endpoints(artifacts)
        if not applicable:
            return None
        patched = sum(1 for ep in applicable if ep.installed_updates)
        return int((patched / len(applicable)) * 100)

    # -- policy dimension ------------------------------------------------------

    @staticmethod
    def _policy_passes(p: Policy) -> Optional[bool]:
        """Evaluate one policy record against what that specific setting means.

        Returns True/False when we have a real rule for this policy, or None
        when it's informational (shouldn't be scored) or its value can't be
        interpreted safely — we skip rather than guess.
        """
        if p.policy_type == 'Group Policy':
            return None  # applied-GPO name list is informational, not pass/fail

        # A few settings are security-INVERTED — enabling them is the risk.
        if p.policy_name == 'ClearTextPassword':
            return p.status == 'Disabled'

        # Numeric settings with a real minimum threshold.
        thresholds = {
            'MinimumPasswordLength': lambda v: v >= 14,
            'PasswordHistorySize': lambda v: v >= 5,
            'LockoutBadCount': lambda v: 0 < v <= 5,
        }
        if p.policy_name in thresholds:
            try:
                return thresholds[p.policy_name](int(p.value))
            except (TypeError, ValueError):
                return None

        if p.policy_type == 'Audit Policy':
            return p.status not in (None, '', 'No Auditing')

        if p.status == 'Enabled':
            return True
        if p.status == 'Disabled':
            return False
        return None  # e.g. "Configured", "Applied" with no specific rule above — skip

    @classmethod
    def _score_policies(cls, artifacts: ArtifactCollection) -> Optional[int]:
        results = [cls._policy_passes(p) for p in artifacts.policies]
        scoreable = [r for r in results if r is not None]
        if not scoreable:
            return None
        return int((sum(1 for r in scoreable if r) / len(scoreable)) * 100)

    # -- event logging dimension ------------------------------------------------

    @classmethod
    def _score_event_logging(cls, artifacts: ArtifactCollection) -> Optional[int]:
        # No events could mean "logging works and nothing bad happened" or
        # "logging is broken" — we can't tell from the artifact alone, so we
        # deliberately return None (not 0, not 100) rather than guess.
        if not artifacts.security_events:
            return None
        critical = sum(1 for e in artifacts.security_events if e.level in ('Critical', 'Error'))
        ratio = critical / len(artifacts.security_events)
        return int(max(0, 100 - (ratio * 100)))

    # -- AD / identity security dimension ---------------------------------------

    @classmethod
    def _score_ad_security(cls, artifacts: ArtifactCollection) -> Optional[int]:
        users = [o for o in artifacts.ad_objects if o.object_class == 'user']
        scoreable = [u for u in users if (u.attributes or {}).get('isStale') is not None]
        if not scoreable:
            return None
        healthy = 0
        for u in scoreable:
            attrs = u.attributes or {}
            disabled = bool(attrs.get('disabled', False))
            stale = bool(attrs.get('isStale', False))
            if disabled or not stale:
                healthy += 1
        return int((healthy / len(scoreable)) * 100)
