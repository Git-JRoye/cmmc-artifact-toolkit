"""Cloud policy collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``PolicyCollector``. Pulls three
distinct policy sources and maps all into the existing ``Policy`` model so
the current scorer, MSP report, and coverage logic work unchanged:

  - Entra Conditional Access policies (identity/access control policy)
  - Intune device configuration profiles (device configuration policy,
    including Windows Update Ring settings mined from the same collection)
  - Intune device compliance policies (the actual configured requirements —
    minimum password length, storage encryption, active firewall, Defender)

Honest scope, matching the pattern set by every other collector in this
project: this reports whether a Conditional Access policy is actually
enforced (state == 'enabled'), not whether its underlying conditions and
grant controls are well-designed — a CA policy that's "enabled" but only
targets a single test user and requires nothing meaningful still counts as
"Enabled" here. Likewise for Intune configuration profiles, this reports
per-profile deployment success/failure counts, not the content of each
platform-specific setting inside the profile (that schema varies enormously
by @odata.type and platform, and parsing every individual setting is a much
larger, separate effort).

Compliance policies are the one place that setting-level content DOES get
parsed — deliberately, to close the exact gap on-prem's Local Security
Policy collector already fills: not just "is this device currently
compliant" but "what does the baseline actually require." Wherever the
underlying concept genuinely matches an on-prem setting (minimum password
length, password complexity), the SAME Policy.policy_name string is reused
on purpose — this means on-prem and cloud evidence for the same real-world
requirement appear together in the same report table and get evaluated by
the exact same pass/fail rule in ComplianceScorer._policy_passes, with zero
new scoring logic needed for those two settings.

HONEST CONFIDENCE NOTE: the Conditional Access endpoint
(identity/conditionalAccess/policies) is a long-stable Graph v1.0 endpoint —
low risk. The Intune per-profile status overview endpoint
(deviceManagement/deviceConfigurations/{id}/deviceStatusOverview) is real and
documented, but has not been pilot-tested against a live tenant as of this
writing — if it 404s or returns an unexpected shape in the real pilot, that's
useful diagnostic information, not necessarily a logic bug.

deviceManagement/deviceCompliancePolicies is ALSO a long-stable v1.0
endpoint (lower risk than detectedApps turned out to be) — but the exact
field names read from the polymorphic windows10CompliancePolicy type below
(especially passwordRequiredType's specific enum values) are recalled with
moderate, not independently verified, confidence. If the real pilot shows
different field names or values, that's genuinely new information to
correct from, not evidence the overall approach is wrong. Only
windows10CompliancePolicy is parsed in depth — this project's on-prem plane
is Windows-only already, and other platform types (iOS/Android/macOS
compliance policies) are logged and skipped rather than guessed at, since
they'd need their own, separately-verified field mappings.

PILOT FINDING (real, confirmed): a first version of this call used
$select with Windows-subtype-specific field names directly on the
deviceCompliancePolicies collection and got a 400 Bad Request against a
real tenant. Best-confidence diagnosis: this collection is a
base/polymorphic type with several subtypes (windows10, android, ios,
macOS...), and Graph commonly rejects $select-ing a subtype-only property
on the base collection endpoint without a type-cast in the URL. Fix
applied: $select was dropped entirely for this one call — full objects
are fetched and read directly, since the per-field mapping already
tolerates any field being absent. Still unverified against a live tenant
as of this writing — if it fails again, the response body is now logged.

Graph application permissions required for this file's full functionality:
  Policy.Read.All (for Conditional Access policies)
  DeviceManagementConfiguration.Read.All (for Intune configuration profiles
  AND compliance policies; DeviceManagementManagedDevices.Read.All, already
  required for the Intune device collector, does NOT cover either of these
  — they are distinct Graph permission scopes)
"""

import logging
from typing import Any, List, Optional

from ..base import CollectorBase
from ...models.artifacts import Policy
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class CloudPolicyCollector(CollectorBase):
    """Collects Entra Conditional Access policies, Intune configuration
    profile deployment status, and Intune compliance policy requirements
    via Microsoft Graph."""

    def __init__(self, graph: GraphClient):
        self.graph = graph

    def collect(self) -> List[Policy]:
        policies: List[Policy] = []
        try:
            policies += self._collect_conditional_access()
        except Exception as e:
            logger.error("Conditional Access policy collection failed: %s", e)
        try:
            policies += self._collect_intune_config_profiles()
        except Exception as e:
            logger.error("Intune configuration profile collection failed: %s", e)
        try:
            policies += self._collect_compliance_policies()
        except Exception as e:
            logger.error("Intune compliance policy collection failed: %s", e)
        logger.info("Cloud policy collection complete: %d record(s)", len(policies))
        return policies

    # -- Conditional Access -------------------------------------------------

    def _collect_conditional_access(self) -> List[Policy]:
        out: List[Policy] = []
        params = {"$select": "id,displayName,state,createdDateTime,modifiedDateTime"}
        for p in self.graph.get_all("identity/conditionalAccess/policies", params=params):
            # Graph's real state values: 'enabled', 'disabled',
            # 'enabledForReportingButNotEnforced'. Mapped to the same
            # Enabled/Disabled vocabulary the rest of the report uses, with
            # the report-only state kept distinguishable in the value field
            # since "reporting but not enforced" is a meaningfully different
            # risk than a plainly disabled policy.
            state = p.get("state") or "unknown"
            status = "Enabled" if state == "enabled" else "Disabled"
            out.append(Policy(
                policy_name=p.get("displayName") or p.get("id") or "Unnamed CA Policy",
                policy_type="Conditional Access",
                status=status,
                target="Tenant",
                value=state,
                description="Entra Conditional Access policy enforcement state",
                last_applied=p.get("modifiedDateTime") or p.get("createdDateTime"),
            ))
        logger.info("  Conditional Access policies: %d", len(out))
        return out

    # -- Intune configuration profiles ---------------------------------------

    def _collect_intune_config_profiles(self) -> List[Policy]:
        """Also mines Windows Update Ring settings out of this SAME
        collection — deviceManagement/deviceConfigurations is polymorphic
        (many profile subtypes), and windowsUpdateForBusinessConfiguration
        is one of them. Deliberately fetches full objects with NO $select
        at all, rather than repeating the exact mistake the compliance
        policy collector just hit for real: $select-ing a subtype-specific
        field name on this kind of collection risks a 400 Bad Request.
        Base fields (id, displayName, lastModifiedDateTime) exist on every
        subtype and are always safe to read via .get() regardless.
        """
        out: List[Policy] = []
        profiles = list(self.graph.get_all("deviceManagement/deviceConfigurations"))
        logger.info("  Intune configuration profiles found: %d", len(profiles))
        for profile in profiles:
            profile_id = profile.get("id")
            name = profile.get("displayName") or profile_id or "Unnamed Configuration Profile"
            odata_type = profile.get("@odata.type", "")

            if odata_type == "#microsoft.graph.windowsUpdateForBusinessConfiguration":
                out.extend(self._map_update_ring_policy(profile, name, profile.get("lastModifiedDateTime")))

            if not profile_id:
                continue
            try:
                overview = self._fetch_status_overview(profile_id)
            except Exception as e:
                logger.warning("  Could not fetch status overview for profile '%s': %s", name, e)
                out.append(Policy(
                    policy_name=name,
                    policy_type="Intune Configuration Profile",
                    status="Unknown",
                    target="Devices",
                    value=None,
                    description="Deployment status could not be retrieved",
                    last_applied=profile.get("lastModifiedDateTime"),
                ))
                continue

            failed = overview.get("errorCount", 0) + overview.get("failedCount", 0)
            success = overview.get("successCount", 0)
            # A profile with zero applicable devices and zero failures isn't
            # "passing" in any meaningful sense — it's simply not deployed
            # anywhere yet. Distinguish that from a real pass/fail verdict.
            if success == 0 and failed == 0:
                status = "Not Applicable"
            else:
                status = "Enabled" if failed == 0 else "Disabled"
            out.append(Policy(
                policy_name=name,
                policy_type="Intune Configuration Profile",
                status=status,
                target="Devices",
                value=f"{success} succeeded / {failed} failed",
                description="Intune device configuration profile deployment status",
                last_applied=profile.get("lastModifiedDateTime"),
            ))
        return out

    def _fetch_status_overview(self, profile_id: str) -> dict:
        return self.graph.get_one(f"deviceManagement/deviceConfigurations/{profile_id}/deviceStatusOverview")

    @staticmethod
    def _map_update_ring_policy(p: dict, policy_name: str, last_modified: Optional[str]) -> List[Policy]:
        """Map one windowsUpdateForBusinessConfiguration object into
        individual Policy rows for the settings that actually matter for
        patch management evidence: how long quality (security) updates are
        deferred, and whether updates install automatically at all rather
        than depending on a user to act.

        HONEST CONFIDENCE NOTE, two layers: (1) field names
        (qualityUpdatesDeferralPeriodInDays, featureUpdatesDeferralPeriodInDays,
        automaticUpdateMode) are recalled with moderate, not independently
        verified, confidence — same caveat as the compliance-policy fields.
        (2) The <=7-day pass/fail threshold on quality-update deferral is a
        reasonable, defensible security judgment (quality updates commonly
        carry security patches, so a long deferral extends real exposure
        time) — it is NOT a literal number CMMC/SI.L1-3.14.1 mandates in
        its text, which only says flaws must be corrected "in a timely
        manner" without specifying days. Treated the same way the existing
        password-length/lockout thresholds already are: a stated, defensible
        judgment call, not a direct quote from the standard.

        Feature-update deferral is shown informationally only (no pass/fail)
        — that setting is primarily about compatibility/stability rollout
        pacing, not security exposure, so judging it pass/fail would overstate
        what this evidence actually proves.
        """
        rows: List[Policy] = []
        target = f"Update Ring: {policy_name}"

        quality_deferral = p.get("qualityUpdatesDeferralPeriodInDays")
        if quality_deferral is not None:
            meets_bar = quality_deferral <= 7
            rows.append(Policy(
                policy_name="QualityUpdateDeferralDays", policy_type="Intune Update Ring",
                status="Enabled" if meets_bar else "Disabled", target=target,
                value=str(quality_deferral),
                description=(f"Quality (security) update deferral period from '{policy_name}' — "
                              f"{quality_deferral} day(s). Longer deferrals delay real security "
                              f"patch exposure (SI.L1-3.14.1); 7 days or fewer is treated as a "
                              f"reasonable bar here, not a literal CMMC-mandated number."),
                last_applied=last_modified,
            ))

        feature_deferral = p.get("featureUpdatesDeferralPeriodInDays")
        if feature_deferral is not None:
            rows.append(Policy(
                policy_name="FeatureUpdateDeferralDays", policy_type="Intune Update Ring",
                status="Configured", target=target, value=str(feature_deferral),
                description=(f"Feature update deferral period from '{policy_name}' — "
                              f"{feature_deferral} day(s) (informational: primarily a "
                              f"stability/compatibility setting, not evaluated pass/fail here)."),
                last_applied=last_modified,
            ))

        auto_mode = p.get("automaticUpdateMode")
        if auto_mode is not None:
            # Known values, moderate confidence: notConfigured, notifyDownload,
            # autoInstallAtMaintenanceTime, autoInstallAndRebootAtMaintenanceTime,
            # autoInstallAndRebootAtScheduledTime, autoInstallAndRebootWithoutEndUserControl,
            # windowsDefault. Treated as meeting the bar only for the states
            # that genuinely apply updates automatically without depending
            # on a user to notice/act.
            auto_installs = str(auto_mode).lower().startswith("autoinstall")
            rows.append(Policy(
                policy_name="AutomaticUpdateMode", policy_type="Intune Update Ring",
                status="Enabled" if auto_installs else "Disabled", target=target,
                value=str(auto_mode),
                description=f"Automatic update installation mode ('{auto_mode}') from '{policy_name}'",
                last_applied=last_modified,
            ))

        return rows

    # -- Intune compliance policies ------------------------------------------

    def _collect_compliance_policies(self) -> List[Policy]:
        """PILOT FINDING (real, confirmed): the first version of this call
        used $select with Windows-subtype-specific fields
        (passwordMinimumLength, storageRequireEncryption, etc.) directly on
        this polymorphic collection and got a 400 Bad Request against a
        real tenant. Best-confidence diagnosis: deviceCompliancePolicies is
        a base/polymorphic type with several subtypes (windows10, android,
        ios, macOS...); Graph commonly rejects $select-ing a subtype-only
        property on the base collection endpoint without a type-cast in
        the URL. Fix applied here: no $select at all — fetch full objects
        and read fields directly (the per-field `.get()` calls below
        already tolerate any field being absent). This is still a
        hypothesis, not confirmed working — if it fails again, the
        response body is now logged so the real error text is available
        instead of guessing a third time.
        """
        out: List[Policy] = []
        try:
            for p in self.graph.get_all("deviceManagement/deviceCompliancePolicies"):
                odata_type = p.get("@odata.type", "")
                name = p.get("displayName") or p.get("id") or "Unnamed Compliance Policy"
                if odata_type != "#microsoft.graph.windows10CompliancePolicy":
                    logger.info(
                        "  Skipping non-Windows compliance policy '%s' (%s) — only "
                        "windows10CompliancePolicy is parsed today", name, odata_type,
                    )
                    continue
                out.extend(self._map_windows_compliance_policy(p, name, p.get("lastModifiedDateTime")))
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Intune compliance policy collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("Intune compliance policy collection failed: %s", e)
            return out
        logger.info("  Intune compliance policies parsed: %d record(s)", len(out))
        return out

    @staticmethod
    def _map_windows_compliance_policy(p: dict, policy_name: str, last_modified: Optional[str]) -> List[Policy]:
        """Map one windows10CompliancePolicy object into individual Policy
        rows, one per setting — same granularity as the on-prem Local
        Security Policy collector, so each requirement gets its own
        pass/fail evaluation instead of one opaque "policy X" verdict.

        Only settings actually present (not None) in the response produce
        a row — a tenant's compliance policy may not configure every
        possible setting, and a missing field is not the same as an
        explicit "not required."
        """
        rows: List[Policy] = []
        target = f"Compliance Policy: {policy_name}"

        min_len = p.get("passwordMinimumLength")
        if min_len is not None:
            rows.append(Policy(
                policy_name="MinimumPasswordLength", policy_type="Intune Compliance Policy",
                status="Configured", target=target, value=str(min_len),
                description=f"Minimum password length required by '{policy_name}'",
                last_applied=last_modified,
            ))

        required_type = p.get("passwordRequiredType")
        if required_type is not None:
            # Known values, moderate confidence (see module docstring):
            # deviceDefault, alphanumeric, numeric, numericComplex. Treated
            # as meeting a complexity bar unless it's the "no real
            # requirement" states (deviceDefault / plain numeric).
            meets_complexity = required_type not in ("deviceDefault", "numeric")
            rows.append(Policy(
                policy_name="PasswordComplexity", policy_type="Intune Compliance Policy",
                status="Enabled" if meets_complexity else "Disabled", target=target,
                value=str(required_type),
                description=f"Password complexity requirement ('{required_type}') from '{policy_name}'",
                last_applied=last_modified,
            ))

        storage_enc = p.get("storageRequireEncryption")
        if storage_enc is not None:
            rows.append(Policy(
                policy_name="StorageRequireEncryption", policy_type="Intune Compliance Policy",
                status="Enabled" if storage_enc else "Disabled", target=target,
                value=str(storage_enc),
                description=f"Storage encryption requirement from '{policy_name}' (SC.L2-3.13.16)",
                last_applied=last_modified,
            ))

        fw_required = p.get("activeFirewallRequired")
        if fw_required is not None:
            rows.append(Policy(
                policy_name="ActiveFirewallRequired", policy_type="Intune Compliance Policy",
                status="Enabled" if fw_required else "Disabled", target=target,
                value=str(fw_required),
                description=f"Active firewall requirement from '{policy_name}'",
                last_applied=last_modified,
            ))

        defender_enabled = p.get("defenderEnabled")
        if defender_enabled is not None:
            rows.append(Policy(
                policy_name="DefenderEnabled", policy_type="Intune Compliance Policy",
                status="Enabled" if defender_enabled else "Disabled", target=target,
                value=str(defender_enabled),
                description=f"Windows Defender requirement from '{policy_name}'",
                last_applied=last_modified,
            ))

        rtp_enabled = p.get("rtpEnabled")
        if rtp_enabled is not None:
            rows.append(Policy(
                policy_name="RealTimeProtectionRequired", policy_type="Intune Compliance Policy",
                status="Enabled" if rtp_enabled else "Disabled", target=target,
                value=str(rtp_enabled),
                description=f"Real-time protection requirement from '{policy_name}'",
                last_applied=last_modified,
            ))

        os_min_version = p.get("osMinimumVersion")
        if os_min_version:
            rows.append(Policy(
                policy_name="OSMinimumVersion", policy_type="Intune Compliance Policy",
                status="Configured", target=target, value=os_min_version,
                description=(f"Minimum OS version requirement from '{policy_name}' "
                              f"(informational — no current baseline to compare against, so this "
                              f"is not evaluated pass/fail)"),
                last_applied=last_modified,
            ))

        return rows
