"""Microsoft Graph authentication and a thin paged client.

Auth is an interface with one working implementation (app-registration /
client-credentials) and documented seams for GDAP and interactive. Each
provider returns a bearer token scoped to the *correct national cloud* for the
tenant, so GCC High "just works" as long as the profile says so.

The GraphClient targets the tenant's Graph base URL and transparently follows
``@odata.nextLink`` paging.

Requires: msal, requests  (add both to requirements.txt)

The secret resolver is intentionally injected. Do NOT read secrets from the
profile or the environment implicitly — pass a callable that looks them up in
your vault, keyed by ``profile.secret_ref``.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Iterator, List, Optional

from .cloud_config import AuthMethod, TenantProfile

logger = logging.getLogger(__name__)

SecretResolver = Callable[[str], str]  # secret_ref -> secret value


class GraphAuthProvider(ABC):
    """Returns a valid Graph bearer token for a given tenant profile."""

    @abstractmethod
    def get_token(self, profile: TenantProfile) -> str:
        ...


class AppRegistrationAuth(GraphAuthProvider):
    """App-only auth via MSAL client credentials.

    Works across commercial and gov clouds because the authority and scope are
    both derived from the tenant's national cloud. Needs an app registration in
    the *matching* cloud (a commercial app cannot authenticate a GCC High
    tenant) with application Graph permissions such as User.Read.All,
    Group.Read.All, Directory.Read.All, AuditLog.Read.All,
    DeviceManagementManagedDevices.Read.All — admin-consented in each tenant.
    """

    def __init__(self, secret_resolver: SecretResolver):
        self._resolve_secret = secret_resolver

    def get_token(self, profile: TenantProfile) -> str:
        import msal  # imported lazily so on-prem-only runs don't need it

        if not (profile.tenant_id and profile.client_id and profile.secret_ref):
            raise ValueError(f"{profile.tenant_key}: tenant_id, client_id and secret_ref are required")

        ep = profile.endpoints()
        app = msal.ConfidentialClientApplication(
            client_id=profile.client_id,
            authority=ep.authority(profile.tenant_id),
            client_credential=self._resolve_secret(profile.secret_ref),
        )
        result = app.acquire_token_for_client(scopes=ep.default_scope())
        if "access_token" not in result:
            raise RuntimeError(
                f"{profile.tenant_key}: token request failed: "
                f"{result.get('error')} - {result.get('error_description')}"
            )
        return result["access_token"]


class GdapAuth(GraphAuthProvider):
    """Delegated access via Partner Center (GDAP).

    Seam only. GDAP token flow differs from app-only, and cross-cloud partner
    management (esp. commercial partner -> GCC High tenant) has real
    limitations — confirm current Partner Center support for your gov clients
    before implementing.
    """

    def get_token(self, profile: TenantProfile) -> str:
        raise NotImplementedError("GDAP auth not yet implemented — see docstring")


class InteractiveAuth(GraphAuthProvider):
    """Device-code / interactive admin sign-in. Seam only."""

    def get_token(self, profile: TenantProfile) -> str:
        raise NotImplementedError("Interactive auth not yet implemented")


def build_auth_provider(method: AuthMethod, secret_resolver: SecretResolver) -> GraphAuthProvider:
    """Factory: pick the provider for a tenant's configured auth method."""
    if method == AuthMethod.APP_REGISTRATION:
        return AppRegistrationAuth(secret_resolver)
    if method == AuthMethod.GDAP:
        return GdapAuth()
    if method == AuthMethod.INTERACTIVE:
        return InteractiveAuth()
    raise ValueError(f"Unknown auth method: {method}")


class GraphClient:
    """Minimal read client for Microsoft Graph, cloud-aware and paged."""

    def __init__(self, profile: TenantProfile, auth: GraphAuthProvider, api_version: str = "v1.0"):
        self.profile = profile
        self.base = f"{profile.endpoints().graph_base}/{api_version}"
        self._auth = auth
        self._token: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        if self._token is None:
            self._token = self._auth.get_token(self.profile)
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def get_all(self, path: str, params: Optional[Dict[str, str]] = None) -> Iterator[Dict[str, Any]]:
        """Yield every item across all pages of a Graph collection endpoint."""
        import requests

        url = f"{self.base}/{path.lstrip('/')}"
        first = True
        while url:
            resp = requests.get(url, headers=self._headers(), params=params if first else None, timeout=60)
            first = False
            if resp.status_code == 429:  # throttled — honor Retry-After
                import time
                wait = int(resp.headers.get("Retry-After", "5"))
                logger.warning("Graph throttled; sleeping %ss", wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            body = resp.json()
            for item in body.get("value", []):
                yield item
            url = body.get("@odata.nextLink")
