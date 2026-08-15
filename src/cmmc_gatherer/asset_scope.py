"""CMMC asset scope categorization.

Implements the 5 asset categories from the CMMC Level 2 Assessment Guide /
CMMC Assessment Scope - Level 2 guide: CUI Assets, Security Protection
Assets (SPA), Contractor Risk Managed Assets (CRMA), Specialized Assets, and
Out-of-Scope Assets. Per that guidance:

  - CUI Assets and SPAs are fully assessed against all applicable practices.
  - CRMA and Specialized Assets are documented (with a stated, risk-based
    reason) but NOT assessed against the practice-by-practice scoring —
    they're reviewed for SSP accuracy only, with the possibility of a
    limited spot-check if something looks questionable.
  - Out-of-Scope Assets are excluded entirely: "should not be part of the
    CMMC assessment engagement" (Assessment Guide language, not a
    paraphrase) — no documentation requirement, no assessment at all.

Design choice, aimed at not making this harder to set up than it needs to
be: everything defaults to CUI Asset (fully assessed) unless explicitly
listed as an exception. A client whose entire environment is in scope
(e.g. a GCC High tenant) needs zero configuration for this feature at all.
Only the assets that AREN'T fully in scope need an entry — typically a
short list, not the whole environment.

Categorization itself is never inferred/guessed at by this tool. The
Assessment Guide is explicit that categorization is a human, policy-driven
decision the contractor must be able to defend ("be ready to defend why an
asset is categorized as Out-of-Scope") — an automated heuristic guess would
not satisfy that, and a wrong guess in the excluding direction (a real CUI
Asset silently marked Out-of-Scope) is a much worse failure than a wrong
guess the other way. So this only ever applies exactly what's declared.
"""

import csv
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AssetCategory(str, Enum):
    CUI_ASSET = "cui_asset"
    SPA = "spa"
    CRMA = "crma"
    SPECIALIZED = "specialized"
    OUT_OF_SCOPE = "out_of_scope"


# Only 3 real behaviors exist even though there are 5 real category names —
# CUI Asset and SPA are treated identically (fully assessed), as are CRMA
# and Specialized (documented, not scored). Kept as named sets rather than
# inline checks so the actual CMMC category names stay visible everywhere
# else (config, report) without every caller re-deriving the behavior split.
_FULLY_ASSESSED = {AssetCategory.CUI_ASSET, AssetCategory.SPA}
_DOCUMENTED_NOT_ASSESSED = {AssetCategory.CRMA, AssetCategory.SPECIALIZED}
_EXCLUDED = {AssetCategory.OUT_OF_SCOPE}


def is_fully_assessed(category: AssetCategory) -> bool:
    return category in _FULLY_ASSESSED


def is_documented_not_assessed(category: AssetCategory) -> bool:
    return category in _DOCUMENTED_NOT_ASSESSED


def is_excluded(category: AssetCategory) -> bool:
    return category in _EXCLUDED


@dataclass(frozen=True)
class AssetException:
    identifier_type: str   # "hostname" or "user"
    identifier: str        # matches Endpoint.hostname, or an AD/Entra user identifier
    category: AssetCategory
    reason: str             # required — the stated justification, reused verbatim in the report


@dataclass
class AssetScope:
    """One tenant's CMMC asset-scope determination: a default category for
    everything collected, plus named exceptions. Defaults to CUI_ASSET so
    a tenant with nothing to exclude needs this block at all."""
    default: AssetCategory = AssetCategory.CUI_ASSET
    exceptions: List[AssetException] = field(default_factory=list)

    def _find(self, identifier_type: str, identifier: str) -> Optional[AssetException]:
        needle = (identifier or "").strip().lower()
        for exc in self.exceptions:
            if exc.identifier_type == identifier_type and exc.identifier.strip().lower() == needle:
                return exc
        return None

    def categorize_hostname(self, hostname: str) -> AssetCategory:
        exc = self._find("hostname", hostname)
        return exc.category if exc else self.default

    def categorize_user(self, identifier: str) -> AssetCategory:
        exc = self._find("user", identifier)
        return exc.category if exc else self.default

    def exception_for_hostname(self, hostname: str) -> Optional[AssetException]:
        return self._find("hostname", hostname)

    def exception_for_user(self, identifier: str) -> Optional[AssetException]:
        return self._find("user", identifier)


_REQUIRED_CSV_COLUMNS = {"identifier_type", "identifier", "category", "reason"}


def load_exceptions_csv(path: str) -> List[AssetException]:
    """Load asset-scope exceptions from a CSV file — meant to be built and
    edited in Excel, not hand-typed YAML, since that's the format an MSP
    admin or business owner already works in day to day.

    Required header row columns: identifier_type, identifier, category, reason

      identifier_type   "hostname" or "user"
      identifier        the hostname (matches an Endpoint's hostname) or
                         user identifier (matches an AD/Entra user's UPN or
                         distinguished name) this exception applies to
      category          one of: cui_asset, spa, crma, specialized, out_of_scope
      reason             required — free text. This is the exact
                         justification your SSP needs anyway for this
                         asset's categorization; it's reused directly in
                         the generated report, not just stored for show.

    Raises a specific, actionable error naming the exact row and problem —
    this file may be edited by someone who isn't a developer, so a bare
    exception here is not an acceptable failure mode.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError(f"Asset exceptions file not found: {path}")

    exceptions: List[AssetException] = []
    # utf-8-sig: Excel writes a BOM at the start of CSVs it saves; plain
    # utf-8 would leave that BOM stuck to the first column's header name.
    with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        if not _REQUIRED_CSV_COLUMNS.issubset(fieldnames):
            missing = _REQUIRED_CSV_COLUMNS - fieldnames
            raise ValueError(
                f"{path}: missing required column(s): {', '.join(sorted(missing))}. "
                f"Header row must contain: {', '.join(sorted(_REQUIRED_CSV_COLUMNS))}"
            )

        for i, row in enumerate(reader, start=2):  # row 1 is the header
            id_type = (row.get("identifier_type") or "").strip().lower()
            identifier = (row.get("identifier") or "").strip()
            category_raw = (row.get("category") or "").strip().lower()
            reason = (row.get("reason") or "").strip()

            if id_type not in ("hostname", "user"):
                raise ValueError(
                    f"{path}, row {i}: identifier_type must be 'hostname' or 'user', "
                    f"got '{id_type}'"
                )
            if not identifier:
                raise ValueError(f"{path}, row {i}: identifier is empty")
            try:
                category = AssetCategory(category_raw)
            except ValueError:
                raise ValueError(
                    f"{path}, row {i}: invalid category '{category_raw}' — must be one "
                    f"of: {', '.join(c.value for c in AssetCategory)}"
                )
            if not reason:
                raise ValueError(
                    f"{path}, row {i}: reason is empty — every exception needs a stated "
                    f"justification (this is exactly what your SSP needs for this asset too)"
                )
            exceptions.append(AssetException(id_type, identifier, category, reason))

    logger.info("Loaded %d asset-scope exception(s) from %s", len(exceptions), path)
    return exceptions


@dataclass
class ScopeApplicationResult:
    """What actually happened when an AssetScope was applied to one real
    collection run — used to build the report's "CMMC Assessment Scope"
    section, so the report can show real counts, not just the config."""
    total_endpoints_seen: int = 0
    total_users_seen: int = 0
    excluded_endpoints: List[str] = field(default_factory=list)
    excluded_users: List[str] = field(default_factory=list)
    documented_endpoints: Dict[str, AssetException] = field(default_factory=dict)
    documented_users: Dict[str, AssetException] = field(default_factory=dict)
    # Exceptions declared in config that never matched anything actually
    # collected — real config drift (a typo, a decommissioned device, a
    # renamed account) worth surfacing rather than silently ignoring.
    unmatched_exceptions: List[AssetException] = field(default_factory=list)


def apply_asset_scope(collection, scope: AssetScope) -> ScopeApplicationResult:
    """Apply an AssetScope to a real ArtifactCollection, in place:
    Out-of-Scope items are removed entirely; CRMA/Specialized items are
    kept but tagged (so they still appear in report tables, just excluded
    from scoring); everything else passes through untouched.

    Mutates `collection.endpoints` / `collection.ad_objects` directly and
    also returns a ScopeApplicationResult summarizing what happened, for
    the report to disclose.
    """
    result = ScopeApplicationResult()
    result.total_endpoints_seen = len(collection.endpoints)
    result.total_users_seen = sum(1 for o in collection.ad_objects if o.object_class == "user")

    matched_hostnames = set()
    kept_endpoints = []
    for ep in collection.endpoints:
        category = scope.categorize_hostname(ep.hostname)
        exc = scope.exception_for_hostname(ep.hostname)
        if exc:
            matched_hostnames.add(exc.identifier.strip().lower())

        if is_excluded(category):
            result.excluded_endpoints.append(ep.hostname)
            continue
        if is_documented_not_assessed(category):
            ep.metadata = dict(ep.metadata or {})
            ep.metadata["asset_category"] = category.value
            ep.metadata["asset_category_reason"] = exc.reason if exc else ""
            result.documented_endpoints[ep.hostname] = exc
        kept_endpoints.append(ep)
    collection.endpoints = kept_endpoints

    matched_users = set()
    kept_ad_objects = []
    for obj in collection.ad_objects:
        if obj.object_class != "user":
            kept_ad_objects.append(obj)
            continue

        identifier = obj.distinguished_name  # UPN for Entra users, DN for on-prem
        category = scope.categorize_user(identifier)
        exc = scope.exception_for_user(identifier)
        if exc:
            matched_users.add(exc.identifier.strip().lower())

        if is_excluded(category):
            result.excluded_users.append(identifier)
            continue
        if is_documented_not_assessed(category):
            obj.attributes = dict(obj.attributes or {})
            obj.attributes["asset_category"] = category.value
            obj.attributes["asset_category_reason"] = exc.reason if exc else ""
            result.documented_users[identifier] = exc
        kept_ad_objects.append(obj)
    collection.ad_objects = kept_ad_objects

    for exc in scope.exceptions:
        key = exc.identifier.strip().lower()
        if exc.identifier_type == "hostname" and key not in matched_hostnames:
            result.unmatched_exceptions.append(exc)
        elif exc.identifier_type == "user" and key not in matched_users:
            result.unmatched_exceptions.append(exc)

    if result.excluded_endpoints or result.excluded_users:
        logger.info(
            "Asset scope applied: excluded %d endpoint(s), %d user(s)",
            len(result.excluded_endpoints), len(result.excluded_users),
        )
    if result.unmatched_exceptions:
        logger.warning(
            "Asset scope: %d exception(s) in config never matched a collected "
            "device/user — possible typo or stale entry: %s",
            len(result.unmatched_exceptions),
            ", ".join(f"{e.identifier_type}:{e.identifier}" for e in result.unmatched_exceptions),
        )

    return result
