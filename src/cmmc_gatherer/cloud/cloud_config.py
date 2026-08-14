"""Cloud environment registry and per-tenant collection profiles.

The two pieces of configuration that let one tool serve commercial, GCC, and
GCC High clients with different access methods:

* ``NATIONAL_CLOUDS`` — maps an environment name to the correct Microsoft Graph
  base URL and login authority. This is the single source of truth for
  "commercial vs GCC High"; collectors never hardcode an endpoint.
* ``TenantProfile`` — describes one client: which cloud, which collection planes
  to run, and which auth method to use. The orchestrator reads this to decide
  what to do for each tenant.

NOTE: Endpoints below are correct to the best of current knowledge but the gov
cloud boundaries evolve — verify against Microsoft's "national cloud deployment"
documentation before production use, especially for GCC High / DoD.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from ..onprem.domain_config import DomainConfig


class NationalCloud(str, Enum):
    COMMERCIAL = "commercial"
    GCC = "gcc"            # rides the commercial cloud
    GCC_HIGH = "gcc_high"  # US Gov cloud
    DOD = "dod"            # US Gov cloud (DoD)


@dataclass(frozen=True)
class CloudEndpoints:
    """Graph base + login authority host for a national cloud."""
    graph_base: str
    authority_host: str  # host only; tenant id is appended per request

    def authority(self, tenant_id: str) -> str:
        return f"https://{self.authority_host}/{tenant_id}"

    def default_scope(self) -> List[str]:
        # Client-credentials flow always uses the resource's /.default scope.
        return [f"{self.graph_base}/.default"]


# GCC uses the *commercial* endpoints; only GCC High and DoD move to the gov cloud.
NATIONAL_CLOUDS: Dict[NationalCloud, CloudEndpoints] = {
    NationalCloud.COMMERCIAL: CloudEndpoints("https://graph.microsoft.com", "login.microsoftonline.com"),
    NationalCloud.GCC:        CloudEndpoints("https://graph.microsoft.com", "login.microsoftonline.com"),
    NationalCloud.GCC_HIGH:   CloudEndpoints("https://graph.microsoft.us", "login.microsoftonline.us"),
    NationalCloud.DOD:        CloudEndpoints("https://dod-graph.microsoft.us", "login.microsoftonline.us"),
}


class AuthMethod(str, Enum):
    APP_REGISTRATION = "app_registration"  # app-only client credentials
    GDAP = "gdap"                          # delegated via Partner Center
    INTERACTIVE = "interactive"            # device-code / interactive admin


class Plane(str, Enum):
    ONPREM = "onprem"  # WinRM / LDAP / GPO
    CLOUD = "cloud"    # Microsoft Graph (Entra + Intune)


@dataclass
class TenantProfile:
    """Everything the orchestrator needs to assess one client."""
    tenant_key: str                       # your internal short name, e.g. "acme"
    display_name: str
    national_cloud: NationalCloud = NationalCloud.COMMERCIAL
    planes: List[Plane] = field(default_factory=lambda: [Plane.CLOUD])
    auth_method: AuthMethod = AuthMethod.APP_REGISTRATION

    # Cloud identifiers (Entra). Secrets are resolved by the auth provider at
    # runtime via secret_ref — never store the secret value in the profile.
    tenant_id: Optional[str] = None       # Entra directory (tenant) GUID
    client_id: Optional[str] = None       # app registration (application) id
    secret_ref: Optional[str] = None      # key into your vault/secret store

    domain_config: Optional[DomainConfig] = None  # on-prem AD connection details, if runs_onprem()

    def endpoints(self) -> CloudEndpoints:
        return NATIONAL_CLOUDS[self.national_cloud]

    def runs_cloud(self) -> bool:
        return Plane.CLOUD in self.planes

    def runs_onprem(self) -> bool:
        return Plane.ONPREM in self.planes

    def deployment_mode(self) -> str:
        """Human-readable label for which plane(s) this tenant runs.

        The `planes` list is the single, simple point of control for
        distinguishing a hybrid client from an on-prem-only or cloud-only
        one — this just gives that a clear label for logging and reporting,
        instead of every caller re-deriving it from runs_onprem()/runs_cloud()
        by hand. Set `planes` once per client in tenants.yaml; everything
        else (which collectors run, device merging, this label) follows
        from that one field automatically.
        """
        onprem, cloud = self.runs_onprem(), self.runs_cloud()
        if onprem and cloud:
            return "hybrid"
        if onprem:
            return "onprem"
        if cloud:
            return "cloud"
        return "none"  # misconfigured — empty planes list, caught by validate()

    def validate(self) -> None:
        """Fail fast with a specific, actionable error if this profile is
        missing required fields for the plane(s) it claims to run — rather
        than silently producing empty or broken collection results deep
        inside a collector, which is a much harder failure to diagnose.

        Called both by the YAML config loader (tenant_config_loader.py) and
        by the orchestrator itself, so a profile built directly in Python
        (e.g. a hand-edited pilot_test.py) gets the same safety net as one
        loaded from tenants.yaml — there's only one place this check lives.

        Only the cloud plane's fields are hard-required here. On-prem's
        domain_config is intentionally NOT required: ActiveDirectoryCollector
        already has a legitimate, working demo-mode fallback when
        domain_config is absent (confirmed against real pilot runs all
        session) — that's a real, supported configuration, not a
        misconfiguration to reject.
        """
        if not self.runs_onprem() and not self.runs_cloud():
            raise ValueError(
                f"Tenant '{self.tenant_key}': planes list is empty — must include "
                f"at least one of {[p.value for p in Plane]}."
            )
        if self.runs_cloud():
            missing = [f for f in ("tenant_id", "client_id", "secret_ref") if not getattr(self, f)]
            if missing:
                raise ValueError(
                    f"Tenant '{self.tenant_key}' has Plane.CLOUD in its planes list but is "
                    f"missing required field(s): {', '.join(missing)}."
                )
