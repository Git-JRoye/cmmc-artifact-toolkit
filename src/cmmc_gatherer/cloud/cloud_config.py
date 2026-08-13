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
