"""Loads tenant profiles from a YAML config file, instead of hand-writing
``TenantProfile`` objects in Python source per client.

This is the piece that actually makes the tool usable by someone other than
its original author: adding a client becomes editing a config file, not
editing source code. Nothing about this file is specific to any one
business — every real client's identifiers live in the config file you
point this at (default: ``tenants.yaml``, which is gitignored), never in
this codebase.

See ``tenants.example.yaml`` at the repo root for the documented format and
a fully worked example with placeholder values.

Secrets are never read from the config file. Each tenant's config only
holds a ``secret_ref`` (a *name*, e.g. "ACME_GRAPH_CLIENT_SECRET") — the
actual secret value is resolved at runtime by whatever ``secret_resolver``
callable the caller supplies (an environment-variable lookup by default;
swap in a real vault lookup for anything beyond a single-operator setup).

HONEST SCOPE NOTE: this only replaces the "how do I add a client without
editing Python" problem. It does not implement GDAP (delegated MSP access
without a per-client app registration) — every cloud tenant configured here
still needs its own app registration and admin-consented permissions,
exactly as documented in cloud/graph.py. GDAP remains the documented,
unimplemented seam it always was.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .cloud.cloud_config import AuthMethod, NationalCloud, Plane, TenantProfile
from .onprem.domain_config import DomainConfig
from .asset_scope import AssetCategory, AssetException, AssetScope, load_exceptions_csv

logger = logging.getLogger(__name__)


class TenantConfigError(ValueError):
    """Raised for a malformed or incomplete tenant config entry.

    Always includes which tenant (by its config-file key) and which field
    caused the problem — this file may be edited by someone who isn't a
    Python developer, so a bare KeyError/AttributeError is not an acceptable
    failure mode here.
    """


def load_tenant_profiles(config_path: str) -> List[TenantProfile]:
    """Read a tenants YAML file and return one TenantProfile per entry.

    Raises TenantConfigError (with the offending tenant key and field named
    explicitly) if a required field is missing or a value isn't one of the
    recognized options. Does not silently skip a bad entry — a config
    mistake should surface immediately and loudly, not quietly produce a
    tenant that fails mysteriously later during collection.
    """
    try:
        import yaml
    except ImportError as e:
        raise TenantConfigError(
            "PyYAML is required to load tenant config files. Install it with: "
            "pip install pyyaml"
        ) from e

    path = Path(config_path)
    if not path.exists():
        raise TenantConfigError(
            f"Tenant config file not found: {config_path}\n"
            f"Copy tenants.example.yaml to {config_path} and fill in your own "
            f"client details, or pass a different --config path."
        )

    with open(path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f) or {}

    entries = raw.get("tenants")
    if not entries:
        raise TenantConfigError(
            f"{config_path} has no 'tenants:' list, or it's empty. "
            f"See tenants.example.yaml for the expected format."
        )
    if not isinstance(entries, list):
        raise TenantConfigError(f"{config_path}: 'tenants:' must be a list of entries, "
                                 f"got {type(entries).__name__}")

    profiles = []
    seen_keys = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TenantConfigError(f"{config_path}: tenant entry #{i + 1} must be a "
                                     f"mapping (key: value pairs), got {type(entry).__name__}")
        profile = _build_profile(entry, index=i + 1, config_path=config_path)
        if profile.tenant_key in seen_keys:
            raise TenantConfigError(f"{config_path}: duplicate tenant_key "
                                     f"'{profile.tenant_key}' — tenant_key must be unique")
        seen_keys.add(profile.tenant_key)
        profiles.append(profile)

    logger.info("Loaded %d tenant profile(s) from %s", len(profiles), config_path)
    return profiles


def _build_profile(entry: Dict[str, Any], index: int, config_path: str) -> TenantProfile:
    tenant_key = entry.get("tenant_key")
    if not tenant_key:
        raise TenantConfigError(f"{config_path}: tenant entry #{index} is missing required "
                                 f"field 'tenant_key' (a short internal name, e.g. 'acme')")

    def require(field_name: str, where: str) -> Any:
        value = entry.get(field_name)
        if value in (None, ""):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' is missing required field "
                f"'{field_name}' ({where})"
            )
        return value

    display_name = entry.get("display_name", tenant_key)

    planes_raw = entry.get("planes")
    if not planes_raw:
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' must specify at least one plane "
            f"under 'planes:' — valid values: {[p.value for p in Plane]}"
        )
    planes = []
    for p in planes_raw:
        try:
            planes.append(Plane(p))
        except ValueError:
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' has invalid plane '{p}' — "
                f"valid values: {[pl.value for pl in Plane]}"
            )

    national_cloud_raw = entry.get("national_cloud", "commercial")
    try:
        national_cloud = NationalCloud(national_cloud_raw)
    except ValueError:
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' has invalid national_cloud "
            f"'{national_cloud_raw}' — valid values: {[c.value for c in NationalCloud]}"
        )

    auth_method_raw = entry.get("auth_method", "app_registration")
    try:
        auth_method = AuthMethod(auth_method_raw)
    except ValueError:
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' has invalid auth_method "
            f"'{auth_method_raw}' — valid values: {[a.value for a in AuthMethod]}"
        )

    tenant_id = client_id = secret_ref = None
    if Plane.CLOUD in planes:
        cloud_cfg = entry.get("cloud")
        if not isinstance(cloud_cfg, dict):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' has 'cloud' in planes but no "
                f"'cloud:' configuration block — needs tenant_id, client_id, secret_ref"
            )
        tenant_id = _require_nested(cloud_cfg, "tenant_id", tenant_key, "cloud", config_path)
        client_id = _require_nested(cloud_cfg, "client_id", tenant_key, "cloud", config_path)
        secret_ref = _require_nested(cloud_cfg, "secret_ref", tenant_key, "cloud", config_path)

    domain_config = None
    if Plane.ONPREM in planes:
        onprem_cfg = entry.get("onprem")
        if not isinstance(onprem_cfg, dict):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' has 'onprem' in planes but no "
                f"'onprem:' configuration block — needs domain_controller, base_dn, "
                f"bind_dn, secret_ref"
            )
        domain_config = DomainConfig(
            domain_controller=_require_nested(onprem_cfg, "domain_controller", tenant_key, "onprem", config_path),
            base_dn=_require_nested(onprem_cfg, "base_dn", tenant_key, "onprem", config_path),
            bind_dn=_require_nested(onprem_cfg, "bind_dn", tenant_key, "onprem", config_path),
            secret_ref=_require_nested(onprem_cfg, "secret_ref", tenant_key, "onprem", config_path),
            port=onprem_cfg.get("port", 636),
            use_ssl=onprem_cfg.get("use_ssl", True),
            page_size=onprem_cfg.get("page_size", 1000),
            stale_after_days=onprem_cfg.get("stale_after_days", 90),
        )

    asset_scope = _build_asset_scope(entry.get("asset_scope"), tenant_key, config_path)

    return TenantProfile(
        tenant_key=tenant_key,
        display_name=display_name,
        national_cloud=national_cloud,
        planes=planes,
        auth_method=auth_method,
        tenant_id=tenant_id,
        client_id=client_id,
        secret_ref=secret_ref,
        domain_config=domain_config,
        asset_scope=asset_scope,
    )


def _build_asset_scope(scope_cfg: Any, tenant_key: str, config_path: str) -> Optional[AssetScope]:
    """Parse an optional 'asset_scope:' block. Entirely optional — a tenant
    with nothing to exclude (e.g. a GCC High client whose whole environment
    is in scope) simply omits this block, and everything defaults to
    CUI_ASSET (fully assessed).

    Supports exceptions inline in YAML, from a CSV file (built/edited in
    Excel — the format most MSP admins already work in), or both at once
    (combined, not one overriding the other).
    """
    if scope_cfg is None:
        return None
    if not isinstance(scope_cfg, dict):
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' has 'asset_scope:' but it isn't a "
            f"mapping (key: value pairs)"
        )

    default_raw = scope_cfg.get("default", "cui_asset")
    try:
        default_category = AssetCategory(default_raw)
    except ValueError:
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' has invalid asset_scope default "
            f"'{default_raw}' — valid values: {[c.value for c in AssetCategory]}"
        )

    exceptions: List[AssetException] = []

    inline = scope_cfg.get("exceptions") or []
    if not isinstance(inline, list):
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions must be a list"
        )
    for i, exc_entry in enumerate(inline, start=1):
        if not isinstance(exc_entry, dict):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions entry #{i} "
                f"must be a mapping (key: value pairs)"
            )
        id_type = exc_entry.get("identifier_type")
        identifier = exc_entry.get("identifier")
        category_raw = exc_entry.get("category")
        reason = exc_entry.get("reason")
        if id_type not in ("hostname", "user"):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions entry #{i} "
                f"has invalid identifier_type '{id_type}' — must be 'hostname' or 'user'"
            )
        if not identifier:
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions entry #{i} "
                f"is missing 'identifier'"
            )
        try:
            category = AssetCategory(category_raw)
        except (ValueError, TypeError):
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions entry #{i} "
                f"has invalid category '{category_raw}' — valid values: "
                f"{[c.value for c in AssetCategory]}"
            )
        if not reason:
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions entry #{i} "
                f"is missing 'reason' — every exception needs a stated justification"
            )
        exceptions.append(AssetException(id_type, identifier, category, reason))

    csv_path = scope_cfg.get("exceptions_file")
    if csv_path:
        try:
            exceptions.extend(load_exceptions_csv(csv_path))
        except ValueError as e:
            raise TenantConfigError(
                f"{config_path}: tenant '{tenant_key}' asset_scope.exceptions_file error: {e}"
            )

    return AssetScope(default=default_category, exceptions=exceptions)


def _require_nested(block: Dict[str, Any], field_name: str, tenant_key: str,
                     section: str, config_path: str) -> Any:
    value = block.get(field_name)
    if value in (None, ""):
        raise TenantConfigError(
            f"{config_path}: tenant '{tenant_key}' is missing required field "
            f"'{field_name}' under '{section}:'"
        )
    return value
