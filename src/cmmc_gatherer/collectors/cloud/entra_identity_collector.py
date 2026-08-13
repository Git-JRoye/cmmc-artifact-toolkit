"""Entra ID identity collector (Microsoft Graph).

The cloud-plane counterpart to the on-prem ActiveDirectoryCollector. Pulls
Entra users and groups, flags the things CMMC assessors care about (guests,
disabled accounts, stale accounts, privileged roles), and maps each into the
existing ``ADObject`` model so the current scorer and exporters work unchanged.

Reusing ADObject is a pragmatic bridge, not the end state: a dedicated
``IdentityObject`` model (cloud-native fields, MFA state, CA coverage) is the
right Phase-3 refactor. Flagged here so it isn't forgotten.

Graph application permissions required: User.Read.All, Group.Read.All, and
AuditLog.Read.All (for signInActivity / stale detection).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

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
        try:
            objects.extend(self._collect_users())
        except Exception as e:  # one source failing shouldn't abort the plane
            logger.error("Entra user collection failed: %s", e)
        try:
            objects.extend(self._collect_groups())
        except Exception as e:
            logger.error("Entra group collection failed: %s", e)
        logger.info("Entra identity collection complete: %d object(s)", len(objects))
        return objects

    # -- users ------------------------------------------------------------

    def _collect_users(self) -> List[ADObject]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.stale_after_days)
        params = {
            "$select": "id,userPrincipalName,displayName,accountEnabled,userType,"
                       "createdDateTime,signInActivity",
            "$top": "999",
        }
        out: List[ADObject] = []
        for u in self.graph.get_all("users", params=params):
            sign_in_activity = u.get("signInActivity")
            data_available = sign_in_activity is not None
            last_sign_in = (sign_in_activity or {}).get("lastSignInDateTime") if sign_in_activity else None
            stale = self._is_stale(last_sign_in, cutoff, data_available)
            out.append(ADObject(
                distinguished_name=u.get("userPrincipalName") or u.get("id") or "unknown",
                object_class="user",
                last_modified=u.get("createdDateTime") or "",
                attributes={
                    "id": u.get("id"),
                    "displayName": u.get("displayName"),
                    "accountEnabled": u.get("accountEnabled"),
                    "userType": u.get("userType"),           # Member / Guest
                    "isGuest": (u.get("userType") == "Guest"),
                    "lastSignIn": last_sign_in,
                    "isStale": stale,
                    "signInDataAvailable": data_available,
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
    def _is_stale(last_sign_in, cutoff: datetime, data_available: bool):
        # No sign-in data at all (commonly: no Entra ID P1 license on this
        # account) means we genuinely cannot tell — return None rather than
        # guessing "stale," which would be a false positive purely due to
        # licensing, not actual inactivity.
        if not data_available:
            return None
        if not last_sign_in:
            return True  # data available, but never signed in = genuinely stale
        try:
            dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
            return dt < cutoff
        except ValueError:
            return False
