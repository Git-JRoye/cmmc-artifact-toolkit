"""Cloud policy collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``PolicyCollector``. Pulls three
distinct policy sources and maps all into the existing ``Policy`` model so
the current scorer, MSP report, and coverage logic work unchanged:

  - Entra Conditional Access policies (identity/access control policy)
  - Intune device configuration profiles (device configuration policy,
    including Windows Update Ring settings mined from the same collection)
  - Intune device compliance policies (the actual configured requirements —
    minimum password length, storage encryption, active firewall, Defender)
  - Intune Endpoint Security policies (deviceManagement/configurationPolicies
    — a genuinely different Graph collection from deviceConfigurations above,
    covering the "Endpoint security" blade in the Intune admin center: EDR,
    Antivirus, Firewall, Disk Encryption, Account Protection, and Attack
    Surface Reduction profiles)

CONFIRMED FIX (verified against real Tenguard tenant 2026-08-17):
  1. deviceManagement/configurationPolicies is a beta-only Graph resource.
     Calling it under /v1.0 produces "Resource not found for the segment
     'configurationPolicies'". Fixed by routing through
     ``self._beta_graph = graph.with_api_version("beta")``.
  2. Per-device deployment status (.../deviceStatuses) does NOT exist on
     this resource — confirmed both via Microsoft's official API reference
     (only two relationships: settings, assignments) and against a real
     tenant ("Resource not found for the segment 'deviceStatuses'" on
     every policy). The ``_fetch_endpoint_security_device_statuses`` method
     has been removed entirely.
  3. Instead, the policy's own ``isAssigned`` boolean (present on the list
     response, no extra API call needed) is used as the status indicator:
     assigned = Enabled, not assigned = Disabled, absent = Unknown.
  4. templateReference.templateFamily correctly identifies Endpoint Security
     categories (endpointSecurityAntivirus, endpointSecurityFirewall,
     endpointSecurityEndpointDetectionAndResponse, etc.) — confirmed
     working against a real tenant with 6 recognized policies and 2
     non-Endpoint-Security ones correctly skipped (templateFamily=none).

Honest scope, matching the pattern set by every other collector in this
project: Conditional Access policies are scored pass/fail strictly on their
enforcement state (state == 'enabled'), BUT the full policy detail —
conditions (who/what/where), grant controls (MFA, compliant device, etc.),
and session controls — is now parsed and displayed in the report so an
assessor can see what each policy actually does, not just that it's
"Enabled". The scoring doesn't judge whether the controls are well-designed
(an enabled policy targeting a single test user still scores "Enabled"),
but the description now makes that visible rather than hiding it.
Likewise for Intune configuration profiles, this reports
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
  DeviceManagementConfiguration.Read.All (for Intune configuration profiles,
  compliance policies, AND endpoint security policies —
  deviceManagement/configurationPolicies is covered by this same scope, no
  new permission needed; DeviceManagementManagedDevices.Read.All, already
  required for the Intune device collector, does NOT cover any of these
  three — they are distinct Graph permission scopes)
"""

import logging
from typing import Any, List, Optional

from ..base import CollectorBase
from ...models.artifacts import Policy
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class CloudPolicyCollector(CollectorBase):
    """Collects Entra Conditional Access policies, Intune configuration
    profile deployment status, Intune compliance policy requirements, and
    Intune Endpoint Security policy deployment status via Microsoft Graph."""

    def __init__(self, graph: GraphClient):
        self.graph = graph
        # deviceManagement/configurationPolicies (Settings Catalog / Endpoint
        # Security policies) is a beta-only Graph resource — confirmed against
        # Microsoft's own Graph API reference (the v1.0 docs for this resource
        # don't exist; the resource and its list operation are documented only
        # under /beta). Calling it under /v1.0 is exactly the "Resource not
        # found for the segment" class of error this project's GraphClient
        # already has a named escape hatch for (see with_api_version's
        # docstring) — same pattern already used by the Intune device
        # collector for its own beta-only calls.
        self._beta_graph = graph.with_api_version("beta")

    def collect(self) -> List[Policy]:
        # Every sub-collection below can involve an unbounded number of
        # sequential Graph calls (one per policy for per-device deployment
        # status), and each only logs a summary line once it FINISHES — so a
        # slow or large tenant previously looked identical to a genuine hang,
        # with no way to tell which of the five sub-collections was actually
        # running. A "Collecting X..." line before each one fixes that: the
        # last printed line always tells you where execution currently is.
        policies: List[Policy] = []
        logger.info("  Collecting Conditional Access policies...")
        try:
            policies += self._collect_conditional_access()
        except Exception as e:
            logger.error("Conditional Access policy collection failed: %s", e)
        logger.info("  Collecting Intune configuration profiles...")
        try:
            policies += self._collect_intune_config_profiles()
        except Exception as e:
            logger.error("Intune configuration profile collection failed: %s", e)
        logger.info("  Collecting Intune compliance policies...")
        try:
            policies += self._collect_compliance_policies()
        except Exception as e:
            logger.error("Intune compliance policy collection failed: %s", e)
        logger.info("  Collecting Intune app protection policies...")
        try:
            policies += self._collect_app_protection_policies()
        except Exception as e:
            logger.error("Intune app protection policy collection failed: %s", e)
        logger.info("  Collecting Intune Endpoint Security policies...")
        try:
            policies += self._collect_endpoint_security_policies()
        except Exception as e:
            logger.error("Intune endpoint security policy collection failed: %s", e)
        logger.info("  Collecting Intune Settings Catalog policies...")
        try:
            policies += self._collect_settings_catalog_policies()
        except Exception as e:
            logger.error("Intune Settings Catalog policy collection failed: %s", e)
        logger.info("Cloud policy collection complete: %d record(s)", len(policies))
        return policies

    # -- Conditional Access -------------------------------------------------

    # Human-readable labels for grantControls.builtInControls values.
    _GRANT_CONTROL_LABELS = {
        'mfa': 'MFA',
        'compliantDevice': 'Compliant Device',
        'domainJoinedDevice': 'Hybrid Azure AD Join',
        'approvedApplication': 'Approved App',
        'compliantApplication': 'App Protection Policy',
        'passwordChange': 'Password Change',
        'block': 'Block Access',
    }

    def _collect_conditional_access(self) -> List[Policy]:
        out: List[Policy] = []
        # No $select — fetch the full CA policy object so we can parse
        # conditions, grantControls, and sessionControls into a meaningful
        # summary for assessors. Zero additional API calls vs the old
        # narrow fetch; the endpoint returns everything in one shot.
        for p in self.graph.get_all("identity/conditionalAccess/policies"):
            # Graph's real state values: 'enabled', 'disabled',
            # 'enabledForReportingButNotEnforced'. Mapped to the same
            # Enabled/Disabled vocabulary the rest of the report uses, with
            # the report-only state kept distinguishable in the value field
            # since "reporting but not enforced" is a meaningfully different
            # risk than a plainly disabled policy.
            state = p.get("state") or "unknown"
            status = "Enabled" if state == "enabled" else "Disabled"
            summary = self._summarize_ca_policy(p)
            out.append(Policy(
                policy_name=p.get("displayName") or p.get("id") or "Unnamed CA Policy",
                policy_type="Conditional Access",
                status=status,
                target=summary.get("target", "Tenant"),
                value=summary.get("value", state),
                description=summary.get("description", "Entra Conditional Access policy"),
                last_applied=p.get("modifiedDateTime") or p.get("createdDateTime"),
            ))
        logger.info("  Conditional Access policies: %d", len(out))
        return out

    @classmethod
    def _summarize_ca_policy(cls, p: dict) -> dict:
        """Parse a full CA policy object into a human-readable summary.

        Returns a dict with 'target', 'value', and 'description' keys
        suitable for the Policy record. Defensive throughout — every field
        might be absent or shaped differently than expected, so .get()
        chains and fallbacks everywhere.
        """
        conditions = p.get("conditions") or {}
        grant = p.get("grantControls") or {}
        session = p.get("sessionControls") or {}

        # -- Who does it target? --
        users_cond = conditions.get("users") or {}
        target_parts: list[str] = []
        inc_users = users_cond.get("includeUsers") or []
        inc_groups = users_cond.get("includeGroups") or []
        inc_roles = users_cond.get("includeRoles") or []
        exc_users = users_cond.get("excludeUsers") or []
        exc_groups = users_cond.get("excludeGroups") or []

        if "All" in inc_users:
            target_parts.append("All Users")
        elif "GuestsOrExternalUsers" in inc_users:
            target_parts.append("Guests/External Users")
        else:
            if inc_users:
                target_parts.append(f"{len(inc_users)} user(s)")
            if inc_groups:
                target_parts.append(f"{len(inc_groups)} group(s)")
        if inc_roles:
            target_parts.append(f"{len(inc_roles)} role(s)")

        exclusion_count = len(exc_users) + len(exc_groups)
        if exclusion_count:
            target_parts.append(f"{exclusion_count} exclusion(s)")

        target_str = ", ".join(target_parts) if target_parts else "Tenant"

        # -- Which apps? --
        apps_cond = conditions.get("applications") or {}
        inc_apps = apps_cond.get("includeApplications") or []
        if "All" in inc_apps:
            apps_str = "All Cloud Apps"
        elif "Office365" in inc_apps:
            apps_str = "Office 365"
        elif inc_apps:
            apps_str = f"{len(inc_apps)} app(s)"
        else:
            apps_str = ""

        # -- What does it require? --
        built_in = grant.get("builtInControls") or []
        operator = grant.get("operator") or "OR"
        control_labels = [cls._GRANT_CONTROL_LABELS.get(c, c) for c in built_in]

        # -- Session controls --
        session_parts: list[str] = []
        sign_in_freq = session.get("signInFrequency") or {}
        if sign_in_freq.get("isEnabled"):
            freq_val = sign_in_freq.get("value", "")
            freq_type = sign_in_freq.get("type", "")
            if freq_val and freq_type:
                session_parts.append(f"sign-in every {freq_val} {freq_type}")
        persist = session.get("persistentBrowser") or {}
        if persist.get("isEnabled"):
            mode = persist.get("mode", "")
            if mode:
                session_parts.append(f"persistent browser: {mode}")

        # -- Platforms --
        platforms_cond = conditions.get("platforms") or {}
        inc_platforms = platforms_cond.get("includePlatforms") or []
        if inc_platforms and "all" not in [s.lower() for s in inc_platforms]:
            platform_str = ", ".join(inc_platforms)
        else:
            platform_str = ""

        # -- Client app types --
        client_types = conditions.get("clientAppTypes") or []

        # -- Risk levels --
        sign_in_risk = conditions.get("signInRiskLevels") or []
        user_risk = conditions.get("userRiskLevels") or []

        # -- Build the compact value line --
        value_parts: list[str] = []
        if control_labels:
            joiner = f" {operator} " if len(control_labels) > 1 else ""
            value_parts.append("Requires: " + joiner.join(control_labels))
        value_parts.append(f"Targets: {target_str}")
        if apps_str:
            value_parts.append(f"Apps: {apps_str}")
        value_line = " | ".join(value_parts) if value_parts else p.get("state", "unknown")

        # -- Build the longer description --
        desc_parts: list[str] = []
        state_label = p.get("state", "unknown")
        desc_parts.append(f"Enforcement: {state_label}.")

        if control_labels:
            joiner = f" {operator} "
            desc_parts.append(f"Grant controls: {joiner.join(control_labels)}.")
        else:
            desc_parts.append("No grant controls configured (allow by default).")

        desc_parts.append(f"Targets {target_str}.")
        if apps_str:
            desc_parts.append(f"Applies to {apps_str}.")
        if platform_str:
            desc_parts.append(f"Platforms: {platform_str}.")
        if client_types:
            desc_parts.append(f"Client types: {', '.join(client_types)}.")
        if sign_in_risk:
            desc_parts.append(f"Sign-in risk levels: {', '.join(sign_in_risk)}.")
        if user_risk:
            desc_parts.append(f"User risk levels: {', '.join(user_risk)}.")
        if session_parts:
            desc_parts.append(f"Session: {'; '.join(session_parts)}.")

        return {
            "target": target_str,
            "value": value_line,
            "description": " ".join(desc_parts),
        }

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

    # -- app protection policies (MAM) ---------------------------------------

    def _collect_app_protection_policies(self) -> List[Policy]:
        """Intune App Protection Policies (MAM — Mobile Application
        Management): controls over corporate DATA within managed apps,
        independent of full device management/compliance. Directly
        relevant to the personally-owned (BYOD) device population this
        project already found real, at scale, in a live pilot (3 of 4
        Tenguard devices) — a device that isn't fully Intune-managed can
        still have its access to corporate data inside specific apps
        (PIN requirement, backup blocked, no "save as" to personal
        storage) controlled this way, which full device Compliance
        Policies don't reach for a BYOD device the same way.

        HONEST CONFIDENCE NOTE: androidManagedAppProtections and
        iosManagedAppProtections are real, documented Intune Graph
        resources, but the exact field names read below are recalled,
        not independently verified against a live tenant — same caveat
        class as every other new endpoint added this session. No $select
        is used, matching the defensive pattern already established for
        the compliance-policy collector above (full objects fetched,
        every field read via .get() so an absent/renamed field degrades
        to "not present" rather than crashing).

        Two separate, non-polymorphic per-platform collections are used
        (not a single base "managedAppPolicies" collection) — deliberately
        avoiding the exact class of problem that broke the compliance-
        policy $select earlier this session (a base/polymorphic type
        rejecting a subtype-only property). Only Android and iOS are
        collected; Windows Information Protection (a related but distinct,
        older feature) is out of scope for this pass.
        """
        out: List[Policy] = []
        for platform, path in (
            ("Android", "deviceAppManagement/androidManagedAppProtections"),
            ("iOS", "deviceAppManagement/iosManagedAppProtections"),
        ):
            try:
                for p in self.graph.get_all(path):
                    name = p.get("displayName") or p.get("id") or f"Unnamed {platform} App Protection Policy"
                    out.extend(self._map_app_protection_policy(p, name, platform, p.get("lastModifiedDateTime")))
            except Exception as e:
                detail = getattr(getattr(e, "response", None), "text", None)
                if detail:
                    logger.error("  %s app protection policy collection failed: %s | Response: %s",
                                 platform, e, detail[:500])
                else:
                    logger.error("  %s app protection policy collection failed: %s", platform, e)
        logger.info("  Intune app protection policies parsed: %d record(s)", len(out))
        return out

    @staticmethod
    def _map_app_protection_policy(p: dict, policy_name: str, platform: str,
                                    last_modified: Optional[str]) -> List[Policy]:
        """Map one app protection policy object into individual Policy
        rows, one per setting — same per-setting granularity as compliance
        policies above, so each requirement gets its own pass/fail
        evaluation. Only settings actually present (not None) produce a
        row.

        Reuses ComplianceScorer._policy_passes' existing generic
        Enabled/Disabled fallback rule — every status value set here is
        exactly "Enabled" or "Disabled", so no new scoring logic is
        needed for this policy type at all.
        """
        rows: List[Policy] = []
        target = f"{platform} App Protection Policy: {policy_name}"

        pin_required = p.get("pinRequired")
        if pin_required is not None:
            rows.append(Policy(
                policy_name="AppProtectionPinRequired", policy_type="Intune App Protection Policy",
                status="Enabled" if pin_required else "Disabled", target=target,
                value=str(pin_required),
                description=f"PIN/passcode requirement to access org data in managed apps ({platform})",
                last_applied=last_modified,
            ))

        backup_blocked = p.get("dataBackupBlocked")
        if backup_blocked is not None:
            rows.append(Policy(
                policy_name="AppProtectionBackupBlocked", policy_type="Intune App Protection Policy",
                status="Enabled" if backup_blocked else "Disabled", target=target,
                value=str(backup_blocked),
                description=f"Org data backup to personal/unmanaged locations blocked ({platform})",
                last_applied=last_modified,
            ))

        save_as_blocked = p.get("saveAsBlocked")
        if save_as_blocked is not None:
            rows.append(Policy(
                policy_name="AppProtectionSaveAsBlocked", policy_type="Intune App Protection Policy",
                status="Enabled" if save_as_blocked else "Disabled", target=target,
                value=str(save_as_blocked),
                description=f"'Save as' to personal/unmanaged storage blocked ({platform})",
                last_applied=last_modified,
            ))

        managed_browser_required = p.get("managedBrowserToOpenLinksRequired")
        if managed_browser_required is not None:
            rows.append(Policy(
                policy_name="AppProtectionManagedBrowserRequired", policy_type="Intune App Protection Policy",
                status="Enabled" if managed_browser_required else "Disabled", target=target,
                value=str(managed_browser_required),
                description=f"Managed browser required to open links from managed apps ({platform})",
                last_applied=last_modified,
            ))

        return rows

    # -- Endpoint Security policies -------------------------------------------

    # Recognized deviceManagementTemplateFamily values for policies that
    # actually live under the Intune admin center's "Endpoint security"
    # blade — recalled with moderate confidence, same caveat class as every
    # other Graph enum in this file. A templateFamily NOT in this dict (e.g.
    # "none", "baseline", or an unrecognized value) means this is a generic
    # Settings Catalog policy, not an Endpoint Security one, and is skipped
    # entirely — this collector's job is Endpoint Security specifically, not
    # every Settings Catalog policy in the tenant.
    _ENDPOINT_SECURITY_TEMPLATE_LABELS = {
        "endpointSecurityAntivirus": "Antivirus",
        "endpointSecurityFirewall": "Firewall",
        "endpointSecurityEndpointDetectionAndResponse": "EDR",
        "endpointSecurityDiskEncryption": "Disk Encryption",
        "endpointSecurityAccountProtection": "Account Protection",
        "endpointSecurityAttackSurfaceReduction": "Attack Surface Reduction",
        "endpointSecurityApplicationControl": "Application Control",
    }

    # Fallback keyword match against templateDisplayName, used only when
    # templateFamily is missing or not one of the recognized values above —
    # per the task's own instruction to identify a policy via templateFamily
    # OR templateDisplayName. Checked in order; first match wins.
    _ENDPOINT_SECURITY_NAME_KEYWORDS = (
        ("antivirus", "Antivirus"),
        ("firewall", "Firewall"),
        ("endpoint detection", "EDR"),
        ("edr", "EDR"),
        ("disk encryption", "Disk Encryption"),
        ("bitlocker", "Disk Encryption"),
        ("account protection", "Account Protection"),
        ("attack surface reduction", "Attack Surface Reduction"),
        ("application control", "Application Control"),
    )

    @classmethod
    def _endpoint_security_template_label(cls, policy: dict) -> Optional[str]:
        """Return a readable Endpoint Security category label (EDR,
        Antivirus, Firewall, ...) for this policy, or None if it doesn't
        look like an Endpoint Security policy at all — the signal to skip
        it rather than report it under this policy_type.

        templateReference.templateFamily is the structured, preferred
        signal; templateDisplayName keyword-matching is only a fallback for
        when templateFamily is absent or unrecognized, per the task's own
        instruction to use "templateFamily or templateDisplayName."
        """
        template_ref = policy.get("templateReference") or {}
        family = template_ref.get("templateFamily")
        if family in cls._ENDPOINT_SECURITY_TEMPLATE_LABELS:
            return cls._ENDPOINT_SECURITY_TEMPLATE_LABELS[family]

        display_name = (template_ref.get("templateDisplayName") or "").lower()
        if display_name:
            for keyword, label in cls._ENDPOINT_SECURITY_NAME_KEYWORDS:
                if keyword in display_name:
                    return label

        # A recognized "endpointSecurity*" family we don't have a specific
        # label for yet is still visibly an Endpoint Security policy — kept
        # visible under a generic label rather than silently dropped, same
        # "no silent caps" discipline used elsewhere in this project (e.g.
        # the software-inventory disclosure notes in the MSP exporter).
        if isinstance(family, str) and family.startswith("endpointSecurity"):
            return "Other Endpoint Security"

        return None

    def _collect_endpoint_security_policies(self) -> List[Policy]:
        """Intune Endpoint Security policies — deviceManagement/
        configurationPolicies, NOT deviceManagement/deviceConfigurations
        (the collection _collect_intune_config_profiles above uses). These
        are two genuinely different Graph collections that happen to serve
        a similar conceptual purpose (device-targeted configuration); this
        one specifically backs the Intune admin center's "Endpoint
        security" blade (EDR, Antivirus, Firewall, Disk Encryption, Account
        Protection, Attack Surface Reduction).

        No $select is used, matching this file's established defensive
        pattern for collections that may reject a subtype/profile-specific
        field name in a base-collection $select (see the compliance-policy
        and configuration-profile collectors above, both of which hit a
        real 400 doing exactly that) — full objects are fetched and every
        field read via .get() so an absent/renamed field degrades to "not
        present" rather than crashing.

        CONFIRMED against a real Tenguard tenant: the configurationPolicies
        list call works under /beta (returns real policies with correct
        templateReference data), and DeviceManagementConfiguration.Read.All
        is sufficient permission. Per-device deployment status (the
        .../deviceStatuses sub-resource this method originally tried) is
        confirmed NOT to exist on this resource — Microsoft's own Graph
        API reference lists only two relationships (settings, assignments),
        and a real tenant confirms "Resource not found for the segment
        'deviceStatuses'" on every policy. Since there is no documented
        Graph API path to get per-device deployment status for
        configurationPolicies, we use the policy's own isAssigned property
        (a boolean already present on the list response) as the best
        available indicator: assigned = actively targeting devices = Enabled;
        not assigned = defined but not deployed = Disabled.
        """
        out: List[Policy] = []
        try:
            for p in self._beta_graph.get_all("deviceManagement/configurationPolicies"):
                policy_id = p.get("id")
                # Beta API uses "name" (not "displayName") for this resource.
                name = p.get("name") or p.get("displayName") or policy_id or "Unnamed Endpoint Security Policy"
                template_label = self._endpoint_security_template_label(p)
                if template_label is None:
                    logger.info(
                        "  Skipping non-Endpoint-Security configuration policy '%s' "
                        "(templateFamily=%s) — not one of the recognized Endpoint "
                        "Security categories", name,
                        (p.get("templateReference") or {}).get("templateFamily"),
                    )
                    continue

                if not policy_id:
                    continue

                # isAssigned is documented as a property of this resource but
                # may not be returned in the list response for all tenants.
                # If it's absent, fall back to fetching the assignments
                # relationship directly — an empty list means "not deployed".
                is_assigned = p.get("isAssigned")
                if is_assigned is None:
                    try:
                        assignments = list(self._beta_graph.get_all(
                            f"deviceManagement/configurationPolicies/{policy_id}/assignments"
                        ))
                        is_assigned = len(assignments) > 0
                    except Exception:
                        pass  # leave as None → "Unknown"

                if is_assigned is True:
                    status = "Enabled"
                    value = "Assigned to device/user groups"
                elif is_assigned is False:
                    status = "Disabled"
                    value = "Not assigned — policy defined but not deployed"
                else:
                    status = "Unknown"
                    value = "Assignment status not available"

                out.append(Policy(
                    policy_name=name,
                    policy_type="Intune Endpoint Security",
                    status=status,
                    target="Devices",
                    value=value,
                    description=f"Endpoint Security policy ({template_label})",
                    last_applied=p.get("lastModifiedDateTime"),
                ))
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Intune endpoint security policy collection failed: %s | Response: %s",
                             e, detail[:500])
            else:
                logger.error("Intune endpoint security policy collection failed: %s", e)
            return out
        logger.info("  Intune endpoint security policies parsed: %d record(s)", len(out))
        return out

    # -- Settings Catalog policies (templateFamily=none) ----------------------

    # Maps the TAIL of a settingDefinitionId (lowercased, after the last
    # recognized CSP-area prefix) to a (policy_name, value_type) pair.
    # policy_name deliberately reuses the SAME names the on-prem Local
    # Security Policy collector and the compliance-policy mapper already use
    # — so the scorer's existing _policy_passes thresholds evaluate them
    # without any new scoring logic.
    #
    # value_type controls how the raw Graph value is extracted:
    #   'integer' → simpleSettingValue.value (int)
    #   'choice'  → choiceSettingValue.value (string, typically ends with
    #               _0 or _1 for boolean-style choices)
    #
    # The DeviceLock CSP contains TWO sets of similarly-named settings:
    #   - Mobile-oriented: MinDevicePasswordLength, DevicePasswordHistory,
    #     MaxDevicePasswordFailedAttempts, DevicePasswordEnabled, …
    #   - Desktop-oriented: MinimumPasswordLength, PasswordHistorySize,
    #     PasswordComplexity, ClearTextPassword, MaximumPasswordAge, …
    #
    # Windows 10/11 Settings Catalog profiles (the kind an MSP creates in
    # the Intune admin center under "Settings catalog" for a CMMC password
    # policy) use the DESKTOP names.  The mobile names are kept as fallbacks
    # in case a profile happens to use them.
    #
    # The LocalPoliciesSecurityOptions CSP does NOT contain password-length,
    # history, complexity, or lockout settings — those all live in DeviceLock.
    # (LocalPoliciesSecurityOptions has InteractiveLogon_MachineInactivityLimit
    # and Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly,
    # which are different controls.)
    #
    # VERIFIED against Microsoft's published DeviceLock CSP reference:
    # learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock
    _SETTINGS_CATALOG_KNOWN_SETTINGS = {
        # DeviceLock CSP — desktop-oriented (primary, used by Settings
        # Catalog profiles on Windows 10/11):
        'devicelock_minimumpasswordlength': ('MinimumPasswordLength', 'integer'),
        'devicelock_passwordhistorysize': ('PasswordHistorySize', 'integer'),
        'devicelock_passwordcomplexity': ('PasswordComplexity', 'integer'),
        'devicelock_maxinactivitytimedevicelock': ('MaxInactivityTimeDeviceLock', 'integer'),
        'devicelock_cleartextpassword': ('ClearTextPassword', 'choice'),
        'devicelock_maximumpasswordage': ('MaximumPasswordAge', 'integer'),
        'devicelock_minimumpasswordage': ('MinimumPasswordAge', 'integer'),
        'devicelock_allowadministratorlockout': ('AllowAdministratorLockout', 'choice'),
        # DeviceLock CSP — mobile-oriented equivalents (fallback — some
        # profiles may use these older setting names):
        'devicelock_mindevicepasswordlength': ('MinimumPasswordLength', 'integer'),
        'devicelock_devicepasswordhistory': ('PasswordHistorySize', 'integer'),
        'devicelock_maxdevicepasswordfailedattempts': ('LockoutBadCount', 'integer'),
        'devicelock_devicepasswordenabled': ('DevicePasswordEnabled', 'choice'),
        'devicelock_alphanumericdevicepasswordrequired': ('AlphanumericPasswordRequired', 'choice'),
        # LocalPoliciesSecurityOptions CSP — inactivity lock (different
        # control from DeviceLock/MaxInactivityTimeDeviceLock — this one
        # is in seconds, the DeviceLock one is in minutes):
        'localpoliciessecurityoptions_interactivelogon_machineinactivitylimit': ('InteractiveLogon_MachineInactivityLimit', 'integer'),
    }

    # CMMC control mappings for Settings Catalog settings — used by the
    # report exporter's control-badge logic. Same format as the compliance
    # policy mapper's implicit mappings.
    _SETTINGS_CATALOG_CMMC_CONTROLS = {
        'MinimumPasswordLength': 'IA.L2-3.5.7',
        'PasswordHistorySize': 'IA.L2-3.5.8',
        'PasswordComplexity': 'IA.L2-3.5.7',
        'LockoutBadCount': 'AC.L2-3.1.8',
        'MaxInactivityTimeDeviceLock': 'AC.L2-3.1.10',
        'ClearTextPassword': 'IA.L2-3.5.7',
        'MaximumPasswordAge': 'IA.L2-3.5.7',
        'MinimumPasswordAge': 'IA.L2-3.5.8',
        'AllowAdministratorLockout': 'AC.L2-3.1.8',
        'DevicePasswordEnabled': 'IA.L2-3.5.7',
        'AlphanumericPasswordRequired': 'IA.L2-3.5.7',
        'InteractiveLogon_MachineInactivityLimit': 'AC.L2-3.1.10',
    }

    def _collect_settings_catalog_policies(self) -> List[Policy]:
        """Parse Settings Catalog configuration profiles (templateFamily=none)
        that the Endpoint Security collector deliberately skips. These are
        the profiles created via the Intune admin center's "Settings catalog"
        picker — they use the same configurationPolicies Graph resource as
        Endpoint Security policies but with templateFamily=none instead of
        an endpointSecurity* family value.

        For each Settings Catalog policy, fetches the individual settings
        via configurationPolicies/{id}/settings and maps recognized
        settingDefinitionId values into Policy objects using the same
        policy_name strings the scorer already knows (MinimumPasswordLength,
        PasswordHistorySize, LockoutBadCount, etc.).

        This is NOT a full Settings Catalog parser — it only extracts
        settings with known, CMMC-relevant settingDefinitionIds. Unrecognized
        settings are logged at DEBUG level for diagnostic visibility but
        do not produce Policy records. This is the same "explicit about what
        we know, honest about what we don't" discipline used throughout this
        collector.
        """
        out: List[Policy] = []
        try:
            for p in self._beta_graph.get_all("deviceManagement/configurationPolicies"):
                template_label = self._endpoint_security_template_label(p)
                if template_label is not None:
                    continue  # Already handled by _collect_endpoint_security_policies

                policy_id = p.get("id")
                if not policy_id:
                    continue

                name = p.get("name") or p.get("displayName") or "Unnamed Settings Catalog Policy"

                # Check assignment status — same logic as endpoint security
                is_assigned = p.get("isAssigned")
                if is_assigned is None:
                    try:
                        assignments = list(self._beta_graph.get_all(
                            f"deviceManagement/configurationPolicies/{policy_id}/assignments"
                        ))
                        is_assigned = len(assignments) > 0
                    except Exception:
                        pass

                if not is_assigned:
                    logger.info("  Settings Catalog policy '%s' is not assigned — skipping setting-level parse", name)
                    continue

                # Fetch individual settings for this policy
                try:
                    settings = list(self._beta_graph.get_all(
                        f"deviceManagement/configurationPolicies/{policy_id}/settings"
                    ))
                except Exception as e:
                    logger.warning("  Could not fetch settings for Settings Catalog policy '%s': %s", name, e)
                    continue

                parsed = self._map_settings_catalog_settings(settings, name, p.get("lastModifiedDateTime"))
                out.extend(parsed)
                logger.info("  Settings Catalog policy '%s': %d recognized setting(s) of %d total",
                            name, len(parsed), len(settings))

        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Settings Catalog policy collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("Settings Catalog policy collection failed: %s", e)
            return out
        logger.info("  Intune Settings Catalog policies parsed: %d record(s)", len(out))
        return out

    @classmethod
    def _map_settings_catalog_settings(cls, settings: list, policy_name: str,
                                        last_modified: Optional[str]) -> List[Policy]:
        """Map individual settings from a Settings Catalog policy into
        Policy records. Each setting's settingDefinitionId is checked
        against _SETTINGS_CATALOG_KNOWN_SETTINGS — recognized settings
        produce a Policy record with the correct policy_name for the
        scorer; unrecognized ones are logged and skipped.
        """
        rows: List[Policy] = []
        target = f"Settings Catalog: {policy_name}"

        for s in settings:
            instance = s.get("settingInstance") or {}
            definition_id = (instance.get("settingDefinitionId") or "").lower()
            if not definition_id:
                continue

            # Match against known settings by checking if the definition ID
            # ends with any of the known suffixes. This handles variations
            # in the prefix (device_vendor_msft_policy_config_ vs other
            # possible prefixes) while still matching on the meaningful
            # CSP area + setting name portion.
            mapping = None
            for suffix, mapped in cls._SETTINGS_CATALOG_KNOWN_SETTINGS.items():
                if definition_id.endswith(suffix):
                    mapping = mapped
                    break

            if mapping is None:
                logger.debug("  Unrecognized Settings Catalog setting: %s", definition_id)
                continue

            policy_name_mapped, value_type = mapping

            # Extract the actual value based on the setting instance type
            value = cls._extract_settings_catalog_value(instance, value_type)
            if value is None:
                logger.debug("  Could not extract value for setting %s (type=%s)",
                             definition_id, instance.get("@odata.type"))
                continue

            # Determine status based on value type and content
            status = cls._settings_catalog_status(policy_name_mapped, value, value_type)

            cmmc_control = cls._SETTINGS_CATALOG_CMMC_CONTROLS.get(policy_name_mapped, '')
            desc = (f"Settings Catalog setting from '{policy_name}'"
                    f"{f' ({cmmc_control})' if cmmc_control else ''}")

            rows.append(Policy(
                policy_name=policy_name_mapped,
                policy_type="Intune Settings Catalog",
                status=status,
                target=target,
                value=str(value),
                description=desc,
                last_applied=last_modified,
            ))

        return rows

    @staticmethod
    def _extract_settings_catalog_value(instance: dict, value_type: str) -> Any:
        """Extract the actual value from a Settings Catalog settingInstance.

        Settings Catalog settings use polymorphic value containers:
        - simpleSettingValue for integers/strings
        - choiceSettingValue for enum/boolean selections
        - groupSettingCollectionValue for grouped settings (not parsed here)
        """
        odata_type = instance.get("@odata.type", "")

        if "SimpleSettingInstance" in odata_type or value_type == 'integer':
            simple_val = instance.get("simpleSettingValue") or {}
            val = simple_val.get("value")
            if val is not None:
                try:
                    return int(val)
                except (TypeError, ValueError):
                    return val

        if "ChoiceSettingInstance" in odata_type or value_type == 'choice':
            choice_val = instance.get("choiceSettingValue") or {}
            val = choice_val.get("value", "")
            return val

        # Fallback: try both containers
        for container_key in ("simpleSettingValue", "choiceSettingValue"):
            container = instance.get(container_key)
            if container and "value" in container:
                return container["value"]

        return None

    @staticmethod
    def _settings_catalog_status(policy_name: str, value: Any, value_type: str) -> str:
        """Determine the status string for a Settings Catalog setting.

        For numeric settings (integer), status is "Configured" — the
        scorer's _policy_passes thresholds handle the actual pass/fail
        evaluation based on the numeric value.

        For choice settings (boolean-style), the value typically ends with
        _1 (enabled) or _0 (disabled). Map those to Enabled/Disabled so
        the scorer's generic fallback rule handles them correctly.
        """
        if value_type == 'integer':
            # Numeric settings are evaluated by the scorer's thresholds,
            # not by status string — use "Configured" to signal that a
            # value is present without pre-judging pass/fail here.
            return "Configured"

        if value_type == 'choice':
            val_str = str(value).lower()
            # Choice values in the Settings Catalog typically end with
            # _1 for "enabled/required" and _0 for "disabled/not required".
            # Also handle plain "enabled"/"disabled" strings.
            if val_str.endswith("_1") or "enabled" in val_str or "required" in val_str:
                return "Enabled"
            if val_str.endswith("_0") or "disabled" in val_str or "notconfigured" in val_str:
                return "Disabled"
            # Unrecognized choice value — log and mark as Configured
            # (not scored) rather than guessing
            return "Configured"

        return "Configured"
