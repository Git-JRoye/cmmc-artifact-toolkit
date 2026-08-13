"""Active Directory object collector (on-prem, via LDAP).

Replaces the original demo stub. Queries a domain controller directly over
LDAP/LDAPS using ldap3 — no RSAT module required, so this can run from a
central Linux, Mac, or Windows collector box reaching into any client domain
it has network access and bind credentials for.

Collects three object classes in separate paged searches: users, groups, and
computers. User and computer entries include memberOf directly — LDAP returns
it as part of the same search, no extra per-object round trip needed, unlike
Entra's Graph API where per-user group expansion is expensive and left empty
for now. Group membership here is populated from the start.

Fallback:
    Pass demo=True (or omit config/secret_resolver) to return canned data —
    lets the pipeline be exercised without a live domain controller.

Requires: ldap3
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ..base import CollectorBase
from ...models.artifacts import ADObject
from ...onprem.domain_config import DomainConfig, SecretResolver
from ...onprem.ldap_client import LdapClient

logger = logging.getLogger(__name__)

_UAC_DISABLED_BIT = 0x2
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# 0 = attribute never set; near-max int64 = AD's "never logged on / never expires" sentinel.
_FILETIME_IGNORE = (0, 9223372036854775807)

_USER_ATTRS = [
    "sAMAccountName", "userAccountControl", "memberOf", "whenCreated",
    "whenChanged", "lastLogonTimestamp", "description",
]
_GROUP_ATTRS = ["sAMAccountName", "description", "whenChanged", "member"]
_COMPUTER_ATTRS = [
    "sAMAccountName", "operatingSystem", "operatingSystemVersion",
    "userAccountControl", "whenChanged", "lastLogonTimestamp", "memberOf",
]

_PRIVILEGED_GROUP_NAMES = (
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
    "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
)


class ActiveDirectoryCollector(CollectorBase):
    """Collects AD users, groups, and computers via direct LDAP queries."""

    def __init__(self, config: Optional[DomainConfig] = None,
                 secret_resolver: Optional[SecretResolver] = None,
                 demo: bool = False):
        self.demo = demo
        self.config = config
        self._client: Optional[LdapClient] = (
            LdapClient(config, secret_resolver) if (config and secret_resolver) else None
        )

    def collect(self) -> List[ADObject]:
        if self.demo or self._client is None:
            logger.info("ActiveDirectoryCollector running in DEMO mode "
                        "(no config/secret_resolver supplied)")
            return self._demo_objects()

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.stale_after_days)
        out: List[ADObject] = []
        try:
            out += self._collect_users(cutoff)
        except Exception as e:
            logger.error("AD user collection failed: %s", e)
        try:
            out += self._collect_groups()
        except Exception as e:
            logger.error("AD group collection failed: %s", e)
        try:
            out += self._collect_computers(cutoff)
        except Exception as e:
            logger.error("AD computer collection failed: %s", e)
        finally:
            self._client.unbind()

        logger.info("AD collection complete: %d object(s)", len(out))
        return out

    # -- users --------------------------------------------------------------

    def _collect_users(self, cutoff: datetime) -> List[ADObject]:
        out: List[ADObject] = []
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        for entry in self._client.search_all(search_filter, _USER_ATTRS):
            uac = self._attr_int(entry, "userAccountControl") or 0
            last_logon = self._filetime_to_dt(self._attr_int(entry, "lastLogonTimestamp"))
            stale = (last_logon is None) or (last_logon < cutoff)
            out.append(ADObject(
                distinguished_name=str(entry.entry_dn),
                object_class="user",
                last_modified=str(self._attr(entry, "whenChanged") or ""),
                attributes={
                    "sAMAccountName": str(self._attr(entry, "sAMAccountName") or ""),
                    "disabled": bool(uac & _UAC_DISABLED_BIT),
                    "lastLogon": last_logon.isoformat() if last_logon else None,
                    "isStale": stale,
                    "whenCreated": str(self._attr(entry, "whenCreated") or ""),
                    "description": str(self._attr(entry, "description") or ""),
                    "isPrivileged": self._is_privileged(self._attr_list(entry, "memberOf")),
                    "source": "onprem_ad",
                },
                group_memberships=self._attr_list(entry, "memberOf"),
            ))
        logger.info("  AD users: %d", len(out))
        return out

    # -- groups ---------------------------------------------------------------

    def _collect_groups(self) -> List[ADObject]:
        out: List[ADObject] = []
        search_filter = "(objectCategory=group)"
        for entry in self._client.search_all(search_filter, _GROUP_ATTRS):
            out.append(ADObject(
                distinguished_name=str(entry.entry_dn),
                object_class="group",
                last_modified=str(self._attr(entry, "whenChanged") or ""),
                attributes={
                    "sAMAccountName": str(self._attr(entry, "sAMAccountName") or ""),
                    "description": str(self._attr(entry, "description") or ""),
                    "memberCount": len(self._attr_list(entry, "member")),
                    "source": "onprem_ad",
                },
                group_memberships=[],
            ))
        logger.info("  AD groups: %d", len(out))
        return out

    # -- computers --------------------------------------------------------------

    def _collect_computers(self, cutoff: datetime) -> List[ADObject]:
        out: List[ADObject] = []
        search_filter = "(objectCategory=computer)"
        for entry in self._client.search_all(search_filter, _COMPUTER_ATTRS):
            uac = self._attr_int(entry, "userAccountControl") or 0
            last_logon = self._filetime_to_dt(self._attr_int(entry, "lastLogonTimestamp"))
            stale = (last_logon is None) or (last_logon < cutoff)
            out.append(ADObject(
                distinguished_name=str(entry.entry_dn),
                object_class="computer",
                last_modified=str(self._attr(entry, "whenChanged") or ""),
                attributes={
                    "sAMAccountName": str(self._attr(entry, "sAMAccountName") or ""),
                    "operatingSystem": str(self._attr(entry, "operatingSystem") or ""),
                    "operatingSystemVersion": str(self._attr(entry, "operatingSystemVersion") or ""),
                    "disabled": bool(uac & _UAC_DISABLED_BIT),
                    "lastLogon": last_logon.isoformat() if last_logon else None,
                    "isStale": stale,
                    "source": "onprem_ad",
                },
                group_memberships=self._attr_list(entry, "memberOf"),
            ))
        logger.info("  AD computers: %d", len(out))
        return out

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _attr(entry, name):
        try:
            return getattr(entry, name).value
        except Exception:
            return None

    @staticmethod
    def _attr_list(entry, name) -> List[str]:
        try:
            values = getattr(entry, name).values
            return [str(v) for v in (values or [])]
        except Exception:
            return []

    @classmethod
    def _attr_int(cls, entry, name) -> Optional[int]:
        val = cls._attr(entry, name)
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_privileged(group_memberships: List[str]) -> bool:
        """Flag membership in a well-known privileged AD group.

        Pure post-processing of memberOf DNs we already collect — no
        additional LDAP query needed. Matches on "CN=<name>," within each DN,
        case-insensitive.
        """
        for dn in group_memberships:
            for name in _PRIVILEGED_GROUP_NAMES:
                if f"cn={name.lower()}," in dn.lower():
                    return True
        return False

    @staticmethod
    def _filetime_to_dt(filetime: Optional[int]) -> Optional[datetime]:
        """Convert an AD FILETIME (100ns ticks since 1601-01-01) to a datetime."""
        if not filetime or filetime in _FILETIME_IGNORE:
            return None
        try:
            return _FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def _demo_objects() -> List[ADObject]:
        return [
            ADObject(
                distinguished_name="CN=Demo User,OU=Users,DC=example,DC=local",
                object_class="user",
                last_modified="",
                attributes={
                    "sAMAccountName": "demo.user", "disabled": False,
                    "isStale": False, "source": "demo",
                },
                group_memberships=["CN=Domain Users,CN=Users,DC=example,DC=local"],
            ),
        ]
