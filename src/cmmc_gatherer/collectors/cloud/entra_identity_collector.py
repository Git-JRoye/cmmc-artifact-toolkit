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

Group membership enrichment: per-user memberOf (users/{id}/memberOf) is a
long-stable v1.0 endpoint — meaningfully lower risk than detectedApps, which
turned out to need /beta on the Intune side. Still genuinely unverified
against a live tenant as of this writing, so treat it the same way: if it
404s, check the endpoint version before assuming the logic is wrong.
SCALABILITY NOTE: same per-user fan-out cost as the privileged-role and MFA
lookups (N users = N calls) — fine at Tenguard's scale, worth revisiting for
a large MSP client. memberOf returns groups AND directory roles mixed
together (a polymorphic directoryObject collection); filtered here to
#microsoft.graph.group only, since roles are already collected separately
via _fetch_privileged_role_members and would otherwise be duplicated under a
different label.

Granular authentication method detail (per-user, users/{id}/authentication/
methods): a more precise, more DIRECT signal for IA.L2-3.5.3 than the
existing isMfaRegistered flag alone — this shows WHICH specific method
type(s) a user has registered (FIDO2 key, Microsoft Authenticator, SMS,
etc.), so an account relying only on a known-weaker method (SMS) is
distinguishable from one using a strong method (FIDO2), even though both
show isMfaRegistered=True in the existing MFA registration report.

HONEST, IMPORTANT LIMITATION on federated identities, confirmed as a real
concern before building this rather than after: for a user authenticated
via a federated external IdP (an on-prem AD FS trust, or a third-party IdP
like Okta/Ping federated into Entra), the actual authentication — including
any MFA — happens AT that external IdP, not inside Entra. This endpoint can
show an empty or sparse methods list for such a user NOT because they lack
real MFA, but because Entra itself never brokered that authentication step
and has no visibility into it. This data is deliberately kept as
SUPPLEMENTARY detail only — it never replaces or overrides the existing
isMfaRegistered-based "Privileged Account Without MFA" finding, and is
labeled in the report as reflecting methods registered directly with Entra,
specifically so a federated user's sparse data is never misread as a
confirmed MFA gap.

Graph application permissions required for this file's full functionality:
  User.Read.All, Group.Read.All, AuditLog.Read.All (existing)
  RoleManagement.Read.Directory (NEW — for privileged role membership)
  Reports.Read.All (NEW — for MFA registration status; unverified exact
  requirement, see note above)
  UserAuthenticationMethod.Read.All (NEW — for granular per-user
  authentication method detail; recalled, not independently verified)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...cloud.graph import GraphClient

logger = logging.getLogger(__name__)

_STALE_AFTER_DAYS = 90

# Readable label + strength tier per authentication method @odata.type.
# "not_mfa" methods (password) are listed for completeness but never
# contribute to the weakest-real-MFA-tier calculation, since a password
# is the primary factor, not a second one. An unrecognized @odata.type
# falls back to its raw type name with tier "unknown" rather than being
# silently dropped — see _fetch_auth_method_details' own confidence note.
_AUTH_METHOD_LABELS = {
    "#microsoft.graph.fido2AuthenticationMethod": ("FIDO2 Security Key", "strong"),
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": ("Windows Hello for Business", "strong"),
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": ("Microsoft Authenticator", "strong"),
    "#microsoft.graph.softwareOathAuthenticationMethod": ("Authenticator App (OATH)", "moderate"),
    "#microsoft.graph.phoneAuthenticationMethod": ("Phone (SMS/Voice Call)", "weak"),
    "#microsoft.graph.emailAuthenticationMethod": ("Email", "weak"),
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod": ("Temporary Access Pass", "temporary"),
    "#microsoft.graph.passwordAuthenticationMethod": ("Password", "not_mfa"),
}
_STRENGTH_RANK = {"strong": 3, "moderate": 2, "weak": 1, "temporary": 0, "unknown": 0}


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

    # -- group membership enrichment ----------------------------------------

    def _fetch_user_group_memberships(self, user_id: str) -> List[str]:
        """Per-user group membership via memberOf. Isolated failure — one
        user's lookup failing never affects another user's data, matching
        the pattern the other per-item lookups in this file already use."""
        groups: List[str] = []
        try:
            for obj in self.graph.get_all(f"users/{user_id}/memberOf", params={"$select": "id,displayName"}):
                if obj.get("@odata.type") == "#microsoft.graph.group":
                    groups.append(obj.get("displayName") or obj.get("id") or "Unnamed Group")
        except Exception as e:
            logger.warning("  Could not fetch group memberships for user %s: %s", user_id, e)
        return groups

    # -- granular authentication method detail -------------------------------

    def _fetch_auth_method_details(self, user_id: str) -> Tuple[List[str], Optional[str], bool]:
        """Per-user granular authentication method detail via
        users/{id}/authentication/methods — see the module docstring's
        federated-identity caveat before using this data anywhere.

        Failure here is isolated to this one user — never affects another
        user's data, matching every other per-item lookup in this file.

        Returns (method_labels, weakest_real_mfa_tier, failed):
          method_labels — readable labels for every method found (may
            include "Password", which doesn't count as a second factor)
          weakest_real_mfa_tier — the weakest tier among registered REAL
            MFA methods (excludes Password), or None if no real MFA
            method was found or the lookup failed — never guessed at
          failed — True only if the Graph call itself errored
        """
        try:
            labels: List[str] = []
            tiers: List[str] = []
            for method in self.graph.get_all(f"users/{user_id}/authentication/methods"):
                odata_type = method.get("@odata.type") or ""
                label, tier = _AUTH_METHOD_LABELS.get(
                    odata_type, (odata_type.replace("#microsoft.graph.", "") or "Unknown method", "unknown")
                )
                labels.append(label)
                if tier != "not_mfa":
                    tiers.append(tier)
            weakest = min(tiers, key=lambda t: _STRENGTH_RANK.get(t, 0)) if tiers else None
            return labels, weakest, False
        except Exception as e:
            logger.warning("  Could not fetch authentication method detail for user %s: %s", user_id, e)
            return [], None, True

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
            groups = self._fetch_user_group_memberships(uid) if uid else []
            auth_method_labels, weakest_tier, auth_lookup_failed = (
                self._fetch_auth_method_details(uid) if uid else ([], None, False)
            )

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
                    "authMethodDetails": auth_method_labels,
                    "weakestAuthMethodTier": weakest_tier,
                    "authMethodLookupFailed": auth_lookup_failed,
                    "source": "entra",
                },
                group_memberships=groups,
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
