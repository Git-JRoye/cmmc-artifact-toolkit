"""Entra service principal (enterprise application) inventory collector.

Collects an inventory of every application/service principal registered in
the tenant — the real answer to "what processes have been granted access to
this environment," which IA.L1-3.5.1's own text explicitly covers
("Identify system users, processes acting on behalf of users, and
devices"). A service principal is exactly that: a process acting with its
own identity, not a human one.

Resolves each permission grant's appRoleId GUID back to its actual
human-readable name (e.g. "Directory.ReadWrite.All"), not just a count —
this was originally deferred as a safer, narrower MVP (existence + count
only) until the basic shape was confirmed working against a real tenant,
which it now has been. Any application permission matching a small,
explicit high-privilege watchlist (broad directory read/write, role
management, etc.) is flagged distinctly — real AC.L2-3.1.7 (Privileged
Functions) evidence: which processes hold elevated access, not just that
some inventory of apps exists.

HONEST CONFIDENCE NOTE: GET /servicePrincipals itself is a long-stable,
extremely common v1.0 Graph endpoint — low risk. The per-principal
appRoleAssignments fields used here (resourceId, appRoleId) and the
resource service principal's own appRoles collection are real and
commonly documented shapes, but resolving a GUID to a name through a
second, cached lookup is a more involved chain than anything else in this
file — treat a permission that resolves as "Unknown permission (<guid>)"
as a real signal to check that specific resource's appRoles rather than
an error.

Efficiency note: resolving names naively (one appRoles fetch per grant)
would refetch the SAME resource's role list over and over, since most
apps reference a small handful of resources (Microsoft Graph chief among
them) repeatedly. This collector caches each resource's role list once
per collect() run, so the real Graph traffic stays at roughly one extra
call per UNIQUE resource referenced tenant-wide, not one per grant.

Graph application permission required: Application.Read.All (covers the
servicePrincipals list, each one's own appRoleAssignments, and reading
other service principals' declared appRoles for name resolution).
"""

import logging
from typing import Dict, List, Optional, Tuple

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)

# Application permissions considered high-privilege enough to flag as
# their own finding when held by any service principal — not exhaustive,
# but covers the class of broad directory read/write and role-management
# access that AC.L2-3.1.7 (Privileged Functions) is most concerned with.
_HIGH_PRIVILEGE_PERMISSIONS = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "User.ReadWrite.All",
    "Mail.ReadWrite",
    "Sites.FullControl.All",
    "Group.ReadWrite.All",
}


class ServicePrincipalCollector(CollectorBase):
    """Collects enterprise application / service principal inventory via
    Microsoft Graph, mapped into the existing ADObject model (object_class
    = 'service_principal') so the report's existing table-rendering
    patterns apply without a new model class."""

    def __init__(self, graph: GraphClient):
        self.graph = graph
        # {resource_service_principal_id: {app_role_id: permission_name}} —
        # shared across every principal processed in one collect() call.
        # See module docstring's "Efficiency note".
        self._role_name_cache: Dict[str, Dict[str, str]] = {}

    def collect(self) -> List[ADObject]:
        out: List[ADObject] = []
        params = {"$select": "id,appId,displayName,accountEnabled,servicePrincipalType"}
        try:
            for sp in self.graph.get_all("servicePrincipals", params=params):
                sp_id = sp.get("id")
                name = sp.get("displayName") or sp.get("appId") or "Unnamed Application"
                if sp_id:
                    permission_names, lookup_failed = self._resolve_permission_grants(sp_id, name)
                else:
                    permission_names, lookup_failed = [], False

                high_privilege = sorted(set(permission_names) & _HIGH_PRIVILEGE_PERMISSIONS)

                out.append(ADObject(
                    distinguished_name=name,
                    object_class="service_principal",
                    last_modified="",
                    attributes={
                        "app_id": sp.get("appId"),
                        "account_enabled": sp.get("accountEnabled"),
                        "service_principal_type": sp.get("servicePrincipalType"),
                        "permission_grant_count": len(permission_names),
                        "permission_names": permission_names,
                        "high_privilege_permissions": high_privilege,
                        "permission_lookup_failed": lookup_failed,
                        "source": "entra",
                    },
                    group_memberships=[],
                ))
        except Exception as e:
            logger.error("Service principal (enterprise app) collection failed: %s", e)
        logger.info("Service principal (enterprise app) inventory complete: %d record(s)", len(out))
        return out

    def _resolve_permission_grants(self, sp_id: str, name: str) -> Tuple[List[str], bool]:
        """Return (permission_names, failed) for this service principal —
        each application permission it holds, resolved to its real,
        human-readable name, not just a count. Failure here is isolated to
        this one principal; never affects the rest of the inventory.
        """
        names: List[str] = []
        try:
            for grant in self.graph.get_all(f"servicePrincipals/{sp_id}/appRoleAssignments"):
                resource_id = grant.get("resourceId")
                app_role_id = grant.get("appRoleId")
                if not resource_id or not app_role_id:
                    continue
                role_name = self._resolve_role_name(resource_id, app_role_id)
                names.append(role_name or f"Unknown permission ({app_role_id})")
            return names, False
        except Exception as e:
            logger.warning("  Could not resolve permission grants for '%s': %s", name, e)
            return [], True

    def _resolve_role_name(self, resource_id: str, app_role_id: str) -> Optional[str]:
        """Resolve one appRoleId to its real permission name, fetching and
        caching the target resource's own declared app roles once per
        resource (not once per grant) — see module docstring's
        "Efficiency note"."""
        if resource_id not in self._role_name_cache:
            try:
                resource_sp = self.graph.get_one(
                    f"servicePrincipals/{resource_id}", params={"$select": "id,appRoles"}
                )
                roles = resource_sp.get("appRoles") or []
                self._role_name_cache[resource_id] = {
                    r.get("id"): r.get("value") for r in roles if r.get("id")
                }
            except Exception as e:
                logger.warning("  Could not resolve app roles for resource '%s': %s", resource_id, e)
                self._role_name_cache[resource_id] = {}
        return self._role_name_cache[resource_id].get(app_role_id)
