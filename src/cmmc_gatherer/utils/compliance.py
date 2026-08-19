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
from typing import Any, Dict, Optional

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

    # Human-readable description of what each dimension actually measures,
    # shown alongside the weight/score breakdown in the report so a client
    # or assessor never has to take the final percentage on faith — they can
    # see exactly what was measured, how much it counted, and what it scored.
    DIMENSION_DESCRIPTIONS = {
        'firewall': "Windows Firewall enabled across all profiles (Domain/Private/Public) on on-prem endpoints, plus real per-device firewall status for Intune-managed cloud devices.",
        'antivirus': "Antivirus / Windows Defender real-time protection active on on-prem endpoints, plus real per-device real-time protection status for Intune-managed cloud devices.",
        'updates': "Patch management coverage. Cloud/Intune-managed environments are scored on Windows Update Ring policy configuration — quality-update deferral window (≤7 days) and automatic installation mode. On-prem endpoints are scored on installed patch/hotfix history (presence check, not recency).",
        'policies': "Local security policy, UAC, audit policy, Conditional Access, and Intune configuration profiles meeting their individual baselines.",
        'event_logging': "Ratio of Critical/Error security events to total events collected (lower ratio scores higher).",
        'ad_security': "AD/Entra accounts that are either disabled or not stale (i.e. actively used and appropriately managed).",
    }

    @classmethod
    def _all_dimension_scores(cls, artifacts: ArtifactCollection) -> Dict[str, Optional[int]]:
        """Single source of truth for the six per-dimension scores, shared by
        calculate_overall_score and calculate_coverage so they can never
        silently disagree about which dimensions had data."""
        return {
            'firewall': cls._score_firewall(artifacts),
            'antivirus': cls._score_antivirus(artifacts),
            'updates': cls._score_updates(artifacts),
            'policies': cls._score_policies(artifacts),
            'event_logging': cls._score_event_logging(artifacts),
            'ad_security': cls._score_ad_security(artifacts),
        }

    @classmethod
    def calculate_overall_score(cls, artifacts: ArtifactCollection) -> int:
        """Return a 0-100 compliance score, weighted across applicable dimensions only.

        NOTE: this renormalizes across only the dimensions that had data, so
        a tenant assessed on just one or two dimensions can still show a high
        score even though most of the framework wasn't evaluated. That's
        correct behavior for the score itself (guessing at missing data would
        be worse), but it means the score alone doesn't communicate how much
        of the assessment is actually covered — pair it with
        calculate_coverage() wherever this score is displayed.
        """
        results = cls._all_dimension_scores(artifacts)
        applicable = {k: v for k, v in results.items() if v is not None}
        if not applicable:
            logger.warning("No scoreable dimensions had applicable data — returning 0")
            return 0

        weighted_sum = sum((v / 100) * cls.SCORE_WEIGHTS[k] for k, v in applicable.items())
        weight_total = sum(cls.SCORE_WEIGHTS[k] for k in applicable)
        score = (weighted_sum / weight_total) * 100
        return int(max(0, min(100, score)))

    @classmethod
    def calculate_coverage(cls, artifacts: ArtifactCollection) -> Dict[str, Any]:
        """Report how much of the six-dimension framework was actually
        assessed, so a clean score can't be mistaken for a fully-assessed
        tenant. Coverage is weight-based, not a flat category count — an
        assessment missing two 15-point dimensions is materially different
        from one missing the 20-point ad_security dimension, even though
        both are "missing 2 of 6" by count.
        """
        results = cls._all_dimension_scores(artifacts)
        assessed = [k for k, v in results.items() if v is not None]
        missing = [k for k, v in results.items() if v is None]
        total_weight = sum(cls.SCORE_WEIGHTS.values())
        assessed_weight = sum(cls.SCORE_WEIGHTS[k] for k in assessed)
        return {
            'assessed_dimensions': assessed,
            'missing_dimensions': missing,
            'assessed_count': len(assessed),
            'total_count': len(results),
            'assessed_weight_pct': int(round((assessed_weight / total_weight) * 100)),
        }

    # -- endpoint dimensions (on-prem only — see module docstring) -----------

    # CRMA/Specialized-tagged assets (via asset_scope.apply_asset_scope) are
    # kept visible in report tables but must never contribute to scoring —
    # the CMMC Assessment Guide is explicit that these categories are
    # reviewed for SSP accuracy only, not assessed against the practices.
    _EXCLUDED_FROM_SCORING_CATEGORIES = ('crma', 'specialized')

    @classmethod
    def _is_scoreable_endpoint(cls, ep) -> bool:
        return (ep.metadata or {}).get('asset_category') not in cls._EXCLUDED_FROM_SCORING_CATEGORIES

    @classmethod
    def _is_scoreable_ad_object(cls, obj) -> bool:
        return (obj.attributes or {}).get('asset_category') not in cls._EXCLUDED_FROM_SCORING_CATEGORIES

    @classmethod
    def _onprem_endpoints(cls, artifacts: ArtifactCollection):
        # firewall_status is only ever set by the on-prem collector; cloud
        # (Intune) endpoints leave it None deliberately. Use it as the signal
        # for "this endpoint has on-prem-style data to score."
        return [ep for ep in artifacts.endpoints
                if ep.firewall_status is not None and cls._is_scoreable_endpoint(ep)]

    @classmethod
    def _score_firewall(cls, artifacts: ArtifactCollection) -> Optional[int]:
        """Blends on-prem Windows Firewall status with real, per-device
        cloud (Intune) firewall status — the latter fetched via a bulk
        report call (see intune_device_collector.py's
        _collect_firewall_statuses), not the compliance-policy
        REQUIREMENT check elsewhere in this project. This is the actual
        observed state on cloud-managed devices, closing the gap that
        previously made this dimension always show N/A for cloud-only
        tenants.
        """
        onprem_applicable = cls._onprem_endpoints(artifacts)
        onprem_points = {'Enabled': 100, 'Partial': 50, 'Disabled': 0}
        onprem_scores = [onprem_points.get(ep.firewall_status, 0) for ep in onprem_applicable]

        # Only "Enabled" and "Disabled" are confidently known-good/known-bad
        # labels from a real pilot run. Intune's own admin UI also shows
        # "Limited" and "Temporarily disabled (default)" as possible states,
        # but the exact strings for those aren't confirmed — rather than
        # guess a partial-credit number for a label that's never actually
        # been observed, those (and anything else unrecognized) are excluded
        # from scoring entirely, the same "never guess" discipline used
        # everywhere else in this scorer. Logged so a real occurrence is
        # visible, not silently dropped.
        cloud_known = {'Enabled': 100, 'Disabled': 0}
        cloud_scores = []
        for ep in artifacts.endpoints:
            if ep.firewall_status is not None or not cls._is_scoreable_endpoint(ep):
                continue
            status = (ep.metadata or {}).get('cloud_firewall_status')
            if status in cloud_known:
                cloud_scores.append(cloud_known[status])
            elif status is not None:
                logger.warning("Unrecognized cloud firewall status '%s' excluded from scoring", status)

        all_scores = onprem_scores + cloud_scores
        if not all_scores:
            return None
        return int(sum(all_scores) / len(all_scores))

    @classmethod
    def _score_antivirus(cls, artifacts: ArtifactCollection) -> Optional[int]:
        """Blends on-prem antivirus status with real, per-device cloud
        (Intune-managed) real-time protection status — the latter from
        windowsProtectionState (see intune_device_collector.py's
        _check_realtime_protection, stored as
        metadata['defender_realtime_protection_enabled']), mirroring the
        exact on-prem+cloud blend _score_firewall already does. Closes the
        same "always N/A for cloud-only tenants" gap firewall had — this
        dimension used to only ever look at ep.antivirus_status, which is
        deliberately left None for every cloud device (see
        intune_device_collector.py's _map()), so a cloud-only tenant could
        never score anything but N/A here regardless of real Defender data.
        """
        onprem_applicable = [ep for ep in artifacts.endpoints
                              if ep.antivirus_status is not None and cls._is_scoreable_endpoint(ep)]
        onprem_scores = [100 if ep.antivirus_status == "Active" else 0 for ep in onprem_applicable]

        # True/False from windowsProtectionState is a real, confirmed
        # observed state (not compliance-POLICY intent) — scored directly,
        # same confidence level as firewall's Enabled/Disabled. None (not
        # checked, or the per-device lookup itself failed) is excluded from
        # scoring entirely rather than guessed at, same "never guess"
        # discipline as everywhere else in this scorer.
        cloud_scores = []
        for ep in artifacts.endpoints:
            if ep.antivirus_status is not None or not cls._is_scoreable_endpoint(ep):
                continue
            rtp = (ep.metadata or {}).get('defender_realtime_protection_enabled')
            if rtp is True:
                cloud_scores.append(100)
            elif rtp is False:
                cloud_scores.append(0)

        all_scores = onprem_scores + cloud_scores
        if not all_scores:
            return None
        return int(sum(all_scores) / len(all_scores))

    @classmethod
    def _score_updates(cls, artifacts: ArtifactCollection) -> Optional[int]:
        """Blends on-prem patch history with Intune Update Ring policy
        configuration — the latter proves the organization HAS a managed
        patch deployment process for cloud-managed devices (deferral
        window, automatic installation mode), which is the control-existence
        evidence SI.L1-3.14.1 calls for.

        On-prem: per-endpoint presence of installed patch/hotfix history.
        Cloud: per-setting pass/fail on scoreable Update Ring settings
        (QualityUpdateDeferralDays, AutomaticUpdateMode — same rules
        already used in _map_update_ring_policy).  FeatureUpdateDeferralDays
        is informational-only ("Configured" status) and excluded here,
        same as the generic _policy_passes logic already does.
        """
        # On-prem: same as before — presence check, not recency
        onprem = cls._onprem_endpoints(artifacts)
        onprem_scores = [100 if ep.installed_updates else 0 for ep in onprem]

        # Cloud: Intune Update Ring policies — only the settings that
        # have a real pass/fail verdict (status Enabled/Disabled), not
        # informational-only ones (status "Configured").
        cloud_scores: list[int] = []
        for p in artifacts.policies:
            if p.policy_type != "Intune Update Ring":
                continue
            if p.status == "Enabled":
                cloud_scores.append(100)
            elif p.status == "Disabled":
                cloud_scores.append(0)
            # "Configured" (e.g. FeatureUpdateDeferralDays) — skip

        all_scores = onprem_scores + cloud_scores
        if not all_scores:
            return None
        return int(sum(all_scores) / len(all_scores))

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
            # Session lock after inactivity (AC.L2-3.1.10). Value is in
            # minutes; must be >0 (actually enforced) and <=15 (reasonable
            # upper bound — NIST 800-171 says "after a defined period",
            # 15 minutes is a widely accepted threshold).
            'MaxInactivityTimeDeviceLock': lambda v: 0 < v <= 15,
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
        users = [o for o in artifacts.ad_objects
                 if o.object_class == 'user' and cls._is_scoreable_ad_object(o)]
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
