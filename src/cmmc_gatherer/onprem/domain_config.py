"""On-prem domain configuration.

Mirrors cloud/cloud_config.py's approach for the on-prem plane: a small,
explicit config object describing how to reach one client's Active Directory,
with the secret resolved by reference (never stored inline) — same pattern as
TenantProfile.secret_ref on the cloud side.
"""

from dataclasses import dataclass
from typing import Callable

SecretResolver = Callable[[str], str]  # secret_ref -> secret value


@dataclass
class DomainConfig:
    """Connection details for one client's Active Directory, reachable over
    LDAP/LDAPS from a central collector box — no RSAT module required."""

    domain_controller: str      # hostname or IP of a reachable DC
    base_dn: str                 # e.g. "DC=acme,DC=local"
    bind_dn: str                 # e.g. "svc-cmmc@acme.local" or a full bind DN
    secret_ref: str              # key into your vault/secret store
    port: int = 636               # 636 = LDAPS, 389 = LDAP (prefer LDAPS)
    use_ssl: bool = True
    page_size: int = 1000
    stale_after_days: int = 90   # for last-logon staleness detection
