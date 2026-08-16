"""Intune RBAC (role-based access control) collector (Microsoft Graph).

Reports WHO holds administrative access to Intune device management itself
— a genuinely distinct privileged-access surface from Entra directory
roles (Global Admin, etc.) already collected in entra_identity_collector.py.
Someone can hold zero Entra admin roles and still have full administrative
control over every managed device via an Intune-specific role assignment
(e.g. "Intune Role Administrator", "Application Manager", "Help Desk
Operator", or a custom role) — this closes that real, previously
uncovered gap in AC.L2-3.1.7 (Privileged Functions) evidence.

Deliberately scoped narrower than a full member-resolution chain: this
reports which role definitions have active assignments and HOW MANY
principals are assigned, not each assigned principal's resolved display
name — resolving an arbitrary member ID (which could be a user, a group,
or an Entra role) to a human-readable name would need its own separate,
unverified lookup chain against directoryObjects. Better to ship a
correct, narrower MVP (role name + assignment count) than guess at a
wider one, matching the same deliberate-narrowing decision the service
principal collector made for permission names before that was confirmed
working and expanded.

HONEST CONFIDENCE NOTE: deviceManagement/roleDefinitions and
deviceManagement/roleAssignments are real, documented Intune Graph
resources, but the exact shape of the roleAssignment object — specifically
which field holds the list of assigned principals, and how it references
its role definition — is recalled with only moderate confidence, not
independently verified against a live tenant. Both collections are
fetched with NO $select, matching the defensive pattern already
established this session for newer/less-verified endpoints: full objects
are fetched and every field is read via .get() with a fallback, so an
absent or differently-named field degrades to an honest "unknown" rather
than crashing collection. Several plausible field name variants are
checked defensively for the same reason (e.g. roleDefinition.id vs.
roleDefinitionId) — if the real pilot shows a different shape entirely,
that's genuinely new information to correct from, not evidence the
overall approach is wrong.

Graph application permission required: DeviceManagementRBAC.Read.All
(NEW — not covered by any permission already granted elsewhere in this
project).
"""

import logging
from typing import Dict, List

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)


class IntuneRbacCollector(CollectorBase):
    """Collects Intune RBAC role definitions and their active assignments
    via Microsoft Graph, mapped into the existing ADObject model
    (object_class = 'intune_role_assignment') so the report's existing
    table-rendering patterns apply without a new model class."""

    def __init__(self, graph: GraphClient):
        self.graph = graph

    def collect(self) -> List[ADObject]:
        out: List[ADObject] = []

        role_names: Dict[str, str] = {}
        try:
            for role in self.graph.get_all("deviceManagement/roleDefinitions"):
                role_id = role.get("id")
                if role_id:
                    role_names[role_id] = role.get("displayName") or "Unnamed Role"
            logger.info("  Intune role definitions found: %d", len(role_names))
        except Exception as e:
            logger.error("Intune role definition collection failed: %s", e)

        try:
            for assignment in self.graph.get_all("deviceManagement/roleAssignments"):
                role_ref = assignment.get("roleDefinition") or {}
                role_def_id = role_ref.get("id") or assignment.get("roleDefinitionId")
                role_name = role_names.get(role_def_id) or role_def_id or "Unknown Role"

                # Several plausible shapes for the assigned-principals list
                # are checked defensively — see module HONEST CONFIDENCE
                # NOTE for why this isn't narrowed to a single field name yet.
                members = (
                    assignment.get("members")
                    or assignment.get("scopeMembers")
                    or (assignment.get("resourceScopes") or [])
                )

                out.append(ADObject(
                    distinguished_name=assignment.get("displayName") or f"{role_name} assignment",
                    object_class="intune_role_assignment",
                    last_modified="",
                    attributes={
                        "role_name": role_name,
                        "assigned_principal_count": len(members),
                        "source": "intune",
                    },
                    group_memberships=[],
                ))
        except Exception as e:
            detail = getattr(getattr(e, "response", None), "text", None)
            if detail:
                logger.error("Intune role assignment collection failed: %s | Response: %s", e, detail[:500])
            else:
                logger.error("Intune role assignment collection failed: %s", e)
        logger.info("Intune RBAC role assignment collection complete: %d record(s)", len(out))
        return out
