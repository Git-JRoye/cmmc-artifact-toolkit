"""Windows security policy collector."""

import logging
from typing import List, Optional
from ..base import CollectorBase
from ...models.artifacts import Policy

logger = logging.getLogger(__name__)


class PolicyCollector(CollectorBase):
    """Collects Windows security policy configurations.

    Covers Group Policy Objects, local security policies, Windows Defender
    settings, and audit policy. Requires admin privileges in production.
    Currently returns demo data.
    """

    def collect(self) -> List[Policy]:
        """Return all applied security policy configurations."""
        logger.info("Collecting policy configurations...")
        policies: List[Policy] = []
        try:
            policies.append(Policy(
                policy_name="Account Lockout Threshold",
                policy_type="Group Policy",
                status="Enabled",
                target="Computer",
                value="5 invalid login attempts",
                description="Number of failed logon attempts before account lockout",
                last_applied="2026-05-14T08:00:00Z",
            ))
            logger.info(f"Policy collection complete: {len(policies)} policy(ies)")
        except Exception as e:
            logger.error(f"Failed to collect policies: {e}")
        return policies

    def collect_by_name(self, policy_name: str) -> Optional[Policy]:
        """Return a specific policy by name, or None if not found."""
        logger.debug(f"Querying policy: {policy_name}")
        # TODO: Implement targeted policy query
        return None
