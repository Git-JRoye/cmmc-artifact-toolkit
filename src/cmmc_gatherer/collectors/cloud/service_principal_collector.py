"""Entra service principal (enterprise application) inventory collector.

Collects an inventory of every application/service principal registered in
the tenant — the real answer to "what processes have been granted access to
this environment," which IA.L1-3.5.1's own text explicitly covers
("Identify system users, processes acting on behalf of users, and
devices"). A service principal is exactly that: a process acting with its
own identity, not a human one.

Deliberately scoped narrower than it could be: this collects WHICH
applications exist and HOW MANY permission grants each holds, not WHICH
specific permissions (e.g. "Directory.ReadWrite.All") each one has.
Resolving a permission grant's appRoleId GUID back to a human-readable
permission name requires a second lookup against the resource API's own
declared app roles, which adds real complexity and risk on top of an
already only-moderately-confident endpoint — better to ship a correct,
narrower MVP (existence + count) than a wider one built on a shakier
assumption. Naming the specific permissions is a reasonable next step once
this basic shape is confirmed working against a real tenant.

HONEST CONFIDENCE NOTE: GET /servicePrincipals itself is a long-stable,
extremely common v1.0 Graph endpoint — low risk. The per-principal
appRoleAssignments count is real and documented but has genuine potential
for confusion in Graph's own naming conventions around assignment
direction (what a principal holds vs. what's been granted to others) —
treat a strange-looking count on the real pilot as useful information to
investigate, not necessarily a bug.

Graph application permission required: Application.Read.All (NEW — covers
both the servicePrincipals list and each one's own appRoleAssignments).
"""

import logging
from typing import List

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class ServicePrincipalCollector(CollectorBase):
    """Collects enterprise application / service principal inventory via
    Microsoft Graph, mapped into the existing ADObject model (object_class
    = 'service_principal') so the report's existing table-rendering
    patterns apply without a new model class."""

    def __init__(self, graph: GraphClient):
        self.graph = graph

    def collect(self) -> List[ADObject]:
        out: List[ADObject] = []
        params = {"$select": "id,appId,displayName,accountEnabled,servicePrincipalType"}
        try:
            for sp in self.graph.get_all("servicePrincipals", params=params):
                sp_id = sp.get("id")
                name = sp.get("displayName") or sp.get("appId") or "Unnamed Application"
                if sp_id:
                    grant_count, lookup_failed = self._count_permission_grants(sp_id, name)
                else:
                    grant_count, lookup_failed = 0, False

                out.append(ADObject(
                    distinguished_name=name,
                    object_class="service_principal",
                    last_modified="",
                    attributes={
                        "app_id": sp.get("appId"),
                        "account_enabled": sp.get("accountEnabled"),
                        "service_principal_type": sp.get("servicePrincipalType"),
                        "permission_grant_count": grant_count,
                        "permission_lookup_failed": lookup_failed,
                        "source": "entra",
                    },
                    group_memberships=[],
                ))
        except Exception as e:
            logger.error("Service principal (enterprise app) collection failed: %s", e)
        logger.info("Service principal (enterprise app) inventory complete: %d record(s)", len(out))
        return out

    def _count_permission_grants(self, sp_id: str, name: str) -> tuple:
        """Count application permission grants held by this service
        principal. A count only — see module docstring for why this
        deliberately doesn't resolve grants to specific permission names
        yet. Failure here is isolated to this one principal's count;
        never affects the rest of the inventory.
        """
        try:
            grants = list(self.graph.get_all(f"servicePrincipals/{sp_id}/appRoleAssignments"))
            return len(grants), False
        except Exception as e:
            logger.warning("  Could not count permission grants for '%s': %s", name, e)
            return 0, True
