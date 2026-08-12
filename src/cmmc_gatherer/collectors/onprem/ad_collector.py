"""Active Directory object collector."""

import logging
from typing import List, Optional
from ..base import CollectorBase
from ...models.artifacts import ADObject

logger = logging.getLogger(__name__)


class ActiveDirectoryCollector(CollectorBase):
    """Collects Active Directory objects (users, groups, computers).

    In production this queries a domain controller via LDAP (port 389).
    Currently returns demo data.
    """

    def collect(self) -> List[ADObject]:
        """Return AD objects queried from the domain controller."""
        logger.info("Collecting Active Directory data...")
        ad_objects: List[ADObject] = []
        try:
            ad_objects.append(ADObject(
                distinguished_name="CN=Domain Admins,CN=Users,DC=contoso,DC=com",
                object_class="group",
                last_modified="2026-05-14T10:00:00Z",
                attributes={
                    "sAMAccountName": "Domain Admins",
                    "description": "Designated administrators of the domain",
                    "memberCount": 2,
                },
                group_memberships=[],
            ))
            logger.info(f"AD collection complete: {len(ad_objects)} object(s)")
        except Exception as e:
            logger.error(f"Failed to collect AD data: {e}")
        return ad_objects

    def collect_by_dn(self, distinguished_name: str) -> Optional[ADObject]:
        """Return a single AD object by its Distinguished Name, or None."""
        logger.debug(f"Querying AD object: {distinguished_name}")
        # TODO: Implement targeted LDAP query
        return None
