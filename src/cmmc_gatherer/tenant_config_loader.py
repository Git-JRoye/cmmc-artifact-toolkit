"""Load client profiles from tenants.yaml → List[TenantProfile].

The YAML format is designed so an MSP with 10+ clients only needs to
maintain a short list of tenant IDs and display names — the shared app
registration (client_id, secret_ref) and default settings are defined
once at the top and inherited by every client.

Usage::

    from cmmc_gatherer.tenant_config_loader import load_tenants

    profiles = load_tenants()            # reads ./tenants.yaml
    profiles = load_tenants("path.yaml") # or a specific path

Each returned TenantProfile has already been validated (validate() called),
so the caller can pass them straight to TenantOrchestrator.run_all().
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml  # PyYAML — pip install pyyaml

from .cloud.cloud_config import (
    AuthMethod,
    NationalCloud,
    Plane,
    TenantProfile,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PLANE_MAP = {p.value: p for p in Plane}
_CLOUD_MAP = {c.value: c for c in NationalCloud}
_AUTH_MAP = {a.value: a for a in AuthMethod}


def _parse_planes(raw: Any) -> List[Plane]:
    """Accept a list of strings or a single string like 'cloud'."""
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        key = str(item).lower().strip()
        if key not in _PLANE_MAP:
            raise ValueError(
                f"Unknown plane '{item}' — expected one of {list(_PLANE_MAP.keys())}"
            )
        out.append(_PLANE_MAP[key])
    return out


def _parse_cloud(raw: Any) -> NationalCloud:
    key = str(raw).lower().strip()
    if key not in _CLOUD_MAP:
        raise ValueError(
            f"Unknown national_cloud '{raw}' — expected one of {list(_CLOUD_MAP.keys())}"
        )
    return _CLOUD_MAP[key]


def _parse_auth(raw: Any) -> AuthMethod:
    key = str(raw).lower().strip()
    if key not in _AUTH_MAP:
        raise ValueError(
            f"Unknown auth_method '{raw}' — expected one of {list(_AUTH_MAP.keys())}"
        )
    return _AUTH_MAP[key]


def _build_domain_config(raw: Dict[str, Any]) -> Any:
    """Build a DomainConfig from a YAML dict, importing lazily so the
    module isn't required unless someone actually configures on-prem."""
    from .onprem.domain_config import DomainConfig  # type: ignore[import-untyped]
    return DomainConfig(**raw)


def _build_asset_scope(raw: Dict[str, Any]) -> Any:
    """Build an AssetScope from a YAML dict, importing lazily."""
    from .asset_scope import AssetScope  # type: ignore[import-untyped]
    return AssetScope(**raw)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_tenants(
    config_path: str | Path = "tenants.yaml",
) -> List[TenantProfile]:
    """Read *config_path* and return a validated list of TenantProfiles.

    Raises ``FileNotFoundError`` if the file doesn't exist, ``ValueError``
    for any structural or validation errors in the config.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path.resolve()}\n"
            f"Copy the tenants.yaml template into your working directory and "
            f"fill in your client details."
        )

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")

    # ── Shared app registration ─────────────────────────────────────
    app_section = data.get("app", {})
    shared_client_id: Optional[str] = app_section.get("client_id")
    shared_secret_ref: Optional[str] = app_section.get("secret_ref")

    # ── Defaults ────────────────────────────────────────────────────
    defaults = data.get("defaults", {})
    default_cloud = _parse_cloud(defaults.get("national_cloud", "commercial"))
    default_planes = _parse_planes(defaults.get("planes", ["cloud"]))
    default_auth = _parse_auth(defaults.get("auth_method", "app_registration"))

    # ── Clients ─────────────────────────────────────────────────────
    clients_raw = data.get("clients")
    if not clients_raw:
        raise ValueError(
            f"{path}: 'clients' list is empty or missing — add at least one "
            f"client entry."
        )

    profiles: List[TenantProfile] = []
    seen_keys: set[str] = set()

    for i, entry in enumerate(clients_raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path}: client entry #{i + 1} is not a mapping — "
                f"each entry needs at least tenant_key, display_name, and tenant_id."
            )

        tenant_key = entry.get("tenant_key")
        if not tenant_key:
            raise ValueError(f"{path}: client entry #{i + 1} is missing 'tenant_key'")
        if tenant_key in seen_keys:
            raise ValueError(f"{path}: duplicate tenant_key '{tenant_key}'")
        seen_keys.add(tenant_key)

        display_name = entry.get("display_name", tenant_key)

        # Per-client overrides fall back to shared/default values
        client_id = entry.get("client_id", shared_client_id)
        secret_ref = entry.get("secret_ref", shared_secret_ref)
        tenant_id = entry.get("tenant_id")
        national_cloud = _parse_cloud(entry["national_cloud"]) if "national_cloud" in entry else default_cloud
        planes = _parse_planes(entry["planes"]) if "planes" in entry else default_planes
        auth_method = _parse_auth(entry["auth_method"]) if "auth_method" in entry else default_auth

        # Optional complex objects
        domain_config = None
        if "domain_config" in entry and entry["domain_config"]:
            domain_config = _build_domain_config(entry["domain_config"])

        asset_scope = None
        if "asset_scope" in entry and entry["asset_scope"]:
            asset_scope = _build_asset_scope(entry["asset_scope"])

        profile = TenantProfile(
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

        # validate() catches missing cloud fields, empty planes, etc.
        profile.validate()
        profiles.append(profile)
        logger.info(
            "Loaded tenant '%s' (%s) — %s, %s",
            tenant_key, display_name, national_cloud.value,
            "/".join(p.value for p in planes),
        )

    logger.info("Loaded %d tenant profile(s) from %s", len(profiles), path)
    return profiles
