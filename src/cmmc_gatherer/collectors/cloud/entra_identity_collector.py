"""Entra ID identity collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ActiveDirectoryCollector. Pulls
Entra users and groups, flags the things CMMC assessors care about (guests,
disabled accounts, stale accounts, privileged roles, MFA registration), and
maps each into the existing ``ADObject`` model so the current scorer and
exporters work unchanged.

Reusing ADObject is a pragmatic bridge, not the end state: a dedicated
``IdentityObject`` model (cloud-native fields, MFA state, CA coverage) is the
right Phase-3 refactor. Flagged here so it isn't forgotten.

Privileged role + MFA enrichment (added after reading the actual CMMC L2
assessment guide + Shared Responsibility Matrix template): IA.L2-3.5.3's
literal assessment objective [a] is "privileged accounts are identified" —
this isn't a nice-to-have, it's the named evidence requirement. Both lookups
are wrapped independently so a permission gap on either endpoint degrades to
"unknown" (None) rather than crashing collection or silently claiming
"not privileged" / "not MFA-registered" when we simply don't know.

HONEST CONFIDENCE NOTE: the role-assignment lookup (directoryRoles) is a
long-stable Graph endpoint — low risk. The MFA report endpoint
(reports/authenticationMethods/userRegistrationDetails) has moved between
Graph API versions over time; this is built against v1.0, which may or may
not be correct for a given tenant — if the pilot run 404s on this call, the
fix is likely switching to the beta endpoint, not a logic change.

Graph application permissions required for this file's full functionality:
  User.Read.All, Group.Read.All, AuditLog.Read.All (existing)
  RoleManagement.Read.Directory (NEW — for privileged role membership)
  Reports.Read.All (NEW — for MFA registration status; unverified exact
  requirement, see note above)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)

_STALE_AFTER_DAYS = 90


class EntraIdentityCollector(CollectorBase):
    """Collects Entra ID users and groups via Microsoft Graph."""

    def __init__(self, graph: GraphClient, stale_after_days: int = _STALE_AFTER_DAYS):
        self.graph = graph
        self.stale_after_days = stale_after_days

    def collect(self) -> List[ADObject]:
        objects: List[ADObject] = []

        privileged_by_user_id: Dict[str, List[str]] = {}
        try:
            privileged_by_user_id = self._fetch_privileged_role_members()
        except Exception as e:
            logger.error("Privileged role lookup failed (isPrivileged will be "
                         "unknown, not False, for all users): %s", e)

        mfa_by_user_id: Dict[str, dict] = {}
        try:
            mfa_by_user_id = self._fetch_mfa_status()
        except Exception as e:
            logger.error("MFA registration lookup failed (isMfaRegistered will "
                         "be unknown, not False, for all users): %s", e)

        try:
            objects.extend(self._collect_users(privileged_by_user_id, mfa_by_user_id))
        except Exception as e:
            logger.error("Entra user collection failed: %s", e)
        try:
            objects.extend(self._collect_groups())
        except Exception as e:
            logger.error("Entra group collection failed: %s", e)
        logger.info("Entra identity collection complete: %d object(s)", len(objects))
        return objects

    # -- privileged role enrichment ----------------------------------------

    def _fetch_privileged_role_members(self) -> Dict[str, List[str]]:
        """Return {user_id: [role display names]} for every activated directory role.

        Two Graph calls per role (list roles, then list each role's members)
        — roles are few (typically under a few dozen even in a large tenant),
        so this stays cheap despite the per-role fan-out.
        """
        result: Dict[str, List[str]] = {}
        roles = list(self.graph.get_all("directoryRoles", params={"$select": "id,displayName"}))
        logger.info("  Entra directory roles found: %d", len(roles))
        for role in roles:
            role_name = role.get("displayName") or "Unknown Role"
            role_id = role.get("id")
            if not role_id:
                continue
            try:
                for member in self.graph.get_all(f"directoryRoles/{role_id}/members",
                                                  params={"$select": "id"}):
                    uid = member.get("id")
                    if uid:
                        result.setdefault(uid, []).append(role_name)
            except Exception as e:
                logger.warning("  Could not list members of role '%s': %s", role_name, e)
        return result

    # -- MFA enrichment -----------------------------------------------------

    def _fetch_mfa_status(self) -> Dict[str, dict]:
        """Return {user_id: {'isMfaRegistered': bool, 'methodsRegistered': [...]}}."""
        result: Dict[str, dict] = {}
        params = {"$select": "id,userPrincipalName,isMfaRegistered,methodsRegistered"}
        for record in self.graph.get_all("reports/authenticationMethods/userRegistrationDetails",
                                          params=params):
            uid = record.get("id")
            if uid:
                result[uid] = {
                    "isMfaRegistered": record.get("isMfaRegistered"),
                    "methodsRegistered": record.get("methodsRegistered") or [],
                }
        return result

    # -- users ------------------------------------------------------------

    def _collect_users(self, privileged_by_user_id: Dict[str, List[str]],
                        mfa_by_user_id: Dict[str, dict]) -> List[ADObject]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.stale_after_days)
        params = {
            "$select": "id,userPrincipalName,displayName,accountEnabled,userType,"
                       "createdDateTime,signInActivity",
            "$top": "999",
        }
        out: List[ADObject] = []
        for u in self.graph.get_all("users", params=params):
            uid = u.get("id")
            sign_in_activity = u.get("signInActivity")
            data_available = sign_in_activity is not None
            last_sign_in = (sign_in_activity or {}).get("lastSignInDateTime") if sign_in_activity else None
            stale = self._is_stale(last_sign_in, cutoff, data_available)

            roles = privileged_by_user_id.get(uid, [])
            mfa = mfa_by_user_id.get(uid)

            out.append(ADObject(
                distinguished_name=u.get("userPrincipalName") or uid or "unknown",
                object_class="user",
                last_modified=u.get("createdDateTime") or "",
                attributes={
                    "id": uid,
                    "displayName": u.get("displayName"),
                    "accountEnabled": u.get("accountEnabled"),
                    "userType": u.get("userType"),           # Member / Guest
                    "isGuest": (u.get("userType") == "Guest"),
                    "lastSignIn": last_sign_in,
                    "isStale": stale,
                    "signInDataAvailable": data_available,
                    "privilegedRoles": roles,
                    "isPrivileged": bool(roles) if privileged_by_user_id or roles else None,
                    "isMfaRegistered": mfa.get("isMfaRegistered") if mfa else None,
                    "mfaMethods": mfa.get("methodsRegistered") if mfa else None,
                    "source": "entra",
                },
                group_memberships=[],  # per-user memberOf is expensive; Phase-3 enrichment
            ))
        logger.info("  Entra users: %d", len(out))
        return out

    # -- groups -----------------------------------------------------------

    def _collect_groups(self) -> List[ADObject]:
        params = {
            "$select": "id,displayName,description,securityEnabled,groupTypes,isAssignableToRole",
            "$top": "999",
        }
        out: List[ADObject] = []
        for g in self.graph.get_all("groups", params=params):
            out.append(ADObject(
                distinguished_name=g.get("displayName") or g.get("id") or "unknown",
                object_class="group",
                last_modified="",
                attributes={
                    "id": g.get("id"),
                    "description": g.get("description"),
                    "securityEnabled": g.get("securityEnabled"),
                    "groupTypes": g.get("groupTypes"),
                    "roleAssignable": g.get("isAssignableToRole"),
                    "source": "entra",
                },
                group_memberships=[],
            ))
        logger.info("  Entra groups: %d", len(out))
        return out

    @staticmethod
    def _is_stale(last_sign_in: str, cutoff: datetime, data_available: bool):
        if not data_available:
            return None
        if not last_sign_in:
            return True
        try:
            dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
            return dt < cutoff
        except ValueError:
            return False
