"""Thin LDAP client.

Mirrors cloud/graph.py's shape on purpose: build a connection from a config
object plus an injected secret resolver, then expose a paged search_all()
generator — same rhythm as GraphClient.get_all(), different protocol.

Requires: ldap3
"""

import logging
from typing import Dict, Iterator, List, Optional

from .domain_config import DomainConfig, SecretResolver

logger = logging.getLogger(__name__)


class LdapClient:
    """Binds to one domain controller and pages through LDAP search results."""

    def __init__(self, config: DomainConfig, secret_resolver: SecretResolver):
        self.config = config
        self._resolve_secret = secret_resolver
        self._connection = None

    def _connect(self):
        import ldap3  # imported lazily so cloud-only runs don't need it installed

        if self._connection is not None:
            return self._connection

        server = ldap3.Server(
            self.config.domain_controller,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            get_info=ldap3.NONE,
        )
        password = self._resolve_secret(self.config.secret_ref)
        conn = ldap3.Connection(
            server,
            user=self.config.bind_dn,
            password=password,
            auto_bind=True,
        )
        self._connection = conn
        return conn

    def search_all(self, search_filter: str, attributes: List[str]) -> Iterator[object]:
        """Yield every entry matching search_filter, transparently paging."""
        conn = self._connect()
        cookie: Optional[bytes] = None
        first = True
        while first or cookie:
            first = False
            conn.search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                attributes=attributes,
                paged_size=self.config.page_size,
                paged_cookie=cookie,
            )
            for entry in conn.entries:
                yield entry
            controls = conn.result.get("controls", {}) if conn.result else {}
            paging = controls.get("1.2.840.113556.1.4.319", {})
            cookie = (paging.get("value") or {}).get("cookie")

    def unbind(self):
        if self._connection is not None:
            self._connection.unbind()
            self._connection = None
