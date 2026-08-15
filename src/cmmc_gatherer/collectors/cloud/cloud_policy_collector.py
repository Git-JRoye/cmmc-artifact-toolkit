"""Cloud policy collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``PolicyCollector``. Pulls three
distinct policy sources and maps all into the existing ``Policy`` model so
the current scorer, MSP report, and coverage logic work unchanged:

  - Entra Conditional Access policies (identity/access control policy)
  - Intune device configuration profiles (device configuration policy)
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

Also unverified: whether $select-ing Windows-specific fields on this
polymorphic collection causes an error for non-Windows policy types mixed
into the same response. If the real pilot run errors on this specifically,
the likely fix is dropping $select and filtering client-side instead —
the same kind of fix the detectedApps beta-endpoint issue needed, not a
sign the underlying approach is wrong.

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
        out: List[Policy] = []
        params = {"$select": "id,displayName,lastModifiedDateTime"}
        profiles = list(self.graph.get_all("deviceManagement/deviceConfigurations", params=params))
        logger.info("  Intune configuration profiles found: %d", len(profiles))
        for profile in profiles:
            profile_id = profile.get("id")
            name = profile.get("displayName") or profile_id or "Unnamed Configuration Profile"
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

    # -- Intune compliance policies ------------------------------------------

    def _collect_compliance_policies(self) -> List[Policy]:
        out: List[Policy] = []
        params = {
            "$select": "id,displayName,lastModifiedDateTime,passwordMinimumLength,"
                       "passwordRequiredType,storageRequireEncryption,activeFirewallRequired,"
                       "defenderEnabled,rtpEnabled,osMinimumVersion",
        }
        for p in self.graph.get_all("deviceManagement/deviceCompliancePolicies", params=params):
            odata_type = p.get("@odata.type", "")
            name = p.get("displayName") or p.get("id") or "Unnamed Compliance Policy"
            if odata_type != "#microsoft.graph.windows10CompliancePolicy":
                logger.info(
                    "  Skipping non-Windows compliance policy '%s' (%s) — only "
                    "windows10CompliancePolicy is parsed today", name, odata_type,
                )
                continue
            out.extend(self._map_windows_compliance_policy(p, name, p.get("lastModifiedDateTime")))
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
