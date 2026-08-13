"""Cloud policy collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ``PolicyCollector``. Pulls two
distinct policy sources and maps both into the existing ``Policy`` model so
the current scorer, MSP report, and coverage logic work unchanged:

  - Entra Conditional Access policies (identity/access control policy)
  - Intune device configuration profiles (device configuration policy)

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

HONEST CONFIDENCE NOTE: the Conditional Access endpoint
(identity/conditionalAccess/policies) is a long-stable Graph v1.0 endpoint —
low risk. The Intune per-profile status overview endpoint
(deviceManagement/deviceConfigurations/{id}/deviceStatusOverview) is real and
documented, but has not been pilot-tested against a live tenant as of this
writing — if it 404s or returns an unexpected shape in the real pilot, that's
useful diagnostic information, not necessarily a logic bug.

Graph application permissions required for this file's full functionality:
  Policy.Read.All (NEW — for Conditional Access policies)
  DeviceManagementConfiguration.Read.All (NEW — for Intune configuration
  profiles; DeviceManagementManagedDevices.Read.All, already required for
  the Intune device collector, does NOT cover configuration profiles —
  these are two distinct Graph permission scopes)
"""

import logging
from typing import List

from ..base import CollectorBase
from ...models.artifacts import Policy
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class CloudPolicyCollector(CollectorBase):
    """Collects Entra Conditional Access policies and Intune configuration
    profile deployment status via Microsoft Graph."""

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
