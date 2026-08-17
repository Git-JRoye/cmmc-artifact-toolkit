"""Tests for the three most critical post-fork subsystems that previously
had zero test coverage:

  1. orchestrator._merge_endpoints — hybrid device de-duplication
  2. asset_scope.apply_asset_scope — CMMC asset categorization
  3. utils.compliance.ComplianceScorer — None returns, weight renormalization,
     CRMA/Specialized exclusion

These tests exist so the docs can accurately claim this logic is tested,
and so regressions in scoring/scoping — the kind that silently produce a
wrong compliance number or silently drop devices — are caught immediately.

Runs with: python -m pytest tests/test_merge_scope_scorer.py -v
    or:    python -m unittest tests/test_merge_scope_scorer.py -v

Requires Python 3.12+ (same as the rest of this project — the exporter
uses f-string syntax that was only unblocked in 3.12).
"""

import sys
import os
import unittest

# Allow running from the repo root (python -m pytest tests/...) or from
# anywhere with PYTHONPATH=src already set.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from cmmc_gatherer.models.artifacts import (
    Endpoint, ADObject, SecurityEvent, Policy, ArtifactCollection,
)
from cmmc_gatherer.orchestrator import TenantOrchestrator
from cmmc_gatherer.asset_scope import (
    AssetCategory, AssetException, AssetScope, ScopeApplicationResult,
    apply_asset_scope, load_exceptions_csv,
)
from cmmc_gatherer.utils.compliance import ComplianceScorer


# ---------------------------------------------------------------------------
# Helpers — build minimal valid objects without repeating boilerplate
# ---------------------------------------------------------------------------

def _ep(hostname, firewall=None, antivirus=None, updates=None, metadata=None):
    """Shorthand for an Endpoint with sensible defaults."""
    return Endpoint(
        hostname=hostname,
        ip_address="10.0.0.1",
        os_version="Windows 10",
        firewall_status=firewall,
        antivirus_status=antivirus,
        installed_updates=updates or [],
        metadata=metadata or {},
    )


def _user(dn, is_stale=None, disabled=False, category=None):
    """Shorthand for a user ADObject."""
    attrs = {}
    if is_stale is not None:
        attrs["isStale"] = is_stale
    if disabled:
        attrs["disabled"] = True
    if category:
        attrs["asset_category"] = category
    return ADObject(
        distinguished_name=dn,
        object_class="user",
        last_modified="2026-01-01T00:00:00Z",
        attributes=attrs,
    )


def _group(dn):
    """Shorthand for a group ADObject."""
    return ADObject(
        distinguished_name=dn,
        object_class="group",
        last_modified="2026-01-01T00:00:00Z",
    )


def _event(level="Information"):
    return SecurityEvent(
        event_id=4624, source="Security", timestamp="2026-01-01T00:00:00Z",
        message="test", level=level, computer="PC1",
    )


def _policy(name="TestPolicy", ptype="Local Policy", status="Enabled",
            target="Computer", value=None):
    return Policy(
        policy_name=name, policy_type=ptype, status=status,
        target=target, value=value,
    )


# ===================================================================
# 1. _merge_endpoints
# ===================================================================

class TestMergeEndpoints(unittest.TestCase):
    """Tests for TenantOrchestrator._merge_endpoints — the hybrid device
    de-duplication logic that prevents a machine enrolled in both on-prem
    and Intune from being counted twice."""

    merge = staticmethod(TenantOrchestrator._merge_endpoints)

    # -- basic cases --------------------------------------------------------

    def test_no_overlap_concatenates(self):
        """When on-prem and cloud hostnames don't overlap, all endpoints
        appear in the output — no merging, no dropping."""
        onprem = [_ep("PC-A", firewall="Enabled")]
        cloud = [_ep("PC-B", metadata={"source": "intune"})]
        result = self.merge(onprem, cloud)
        hostnames = {ep.hostname for ep in result}
        self.assertEqual(hostnames, {"PC-A", "PC-B"})
        self.assertEqual(len(result), 2)

    def test_empty_inputs(self):
        self.assertEqual(self.merge([], []), [])
        onprem = [_ep("PC-A", firewall="Enabled")]
        self.assertEqual(len(self.merge(onprem, [])), 1)
        cloud = [_ep("PC-B")]
        self.assertEqual(len(self.merge([], cloud)), 1)

    # -- hostname matching --------------------------------------------------

    def test_case_insensitive_match(self):
        """Hostname matching must be case-insensitive — the same machine
        can report as 'WORKSTATION-1' via on-prem and 'workstation-1' via
        Intune."""
        onprem = [_ep("WORKSTATION-1", firewall="Enabled")]
        cloud = [_ep("workstation-1", metadata={"compliance": "compliant"})]
        result = self.merge(onprem, cloud)
        self.assertEqual(len(result), 1)

    def test_whitespace_trimmed(self):
        """Leading/trailing whitespace in hostnames should not prevent a match."""
        onprem = [_ep("  SERVER-1  ", firewall="Enabled")]
        cloud = [_ep("SERVER-1", metadata={"compliance": "compliant"})]
        result = self.merge(onprem, cloud)
        self.assertEqual(len(result), 1)

    def test_none_hostname_never_matches(self):
        """An endpoint with hostname=None should pass through unmerged,
        not match other None-hostname endpoints."""
        onprem = [_ep(None, firewall="Enabled")]
        cloud = [_ep(None, metadata={"source": "intune"})]
        result = self.merge(onprem, cloud)
        # Both should appear — None hostnames don't match each other
        self.assertEqual(len(result), 2)

    def test_empty_hostname_never_matches(self):
        """An endpoint with hostname='' should behave like None."""
        onprem = [_ep("", firewall="Enabled")]
        cloud = [_ep("", metadata={"source": "intune"})]
        result = self.merge(onprem, cloud)
        self.assertEqual(len(result), 2)

    # -- merged record contents ---------------------------------------------

    def test_merged_record_keeps_onprem_fields(self):
        """The merged record should keep the on-prem endpoint's scoring-
        relevant fields (firewall, antivirus, updates) — those are the
        fields that only on-prem collection produces."""
        onprem = [_ep("HYBRID-PC", firewall="Enabled", antivirus="Active",
                       updates=["KB5001", "KB5002"])]
        cloud = [_ep("hybrid-pc", metadata={"compliance": "compliant",
                                             "encryption": "encrypted"})]
        result = self.merge(onprem, cloud)
        self.assertEqual(len(result), 1)
        merged = result[0]
        self.assertEqual(merged.firewall_status, "Enabled")
        self.assertEqual(merged.antivirus_status, "Active")
        self.assertEqual(merged.installed_updates, ["KB5001", "KB5002"])

    def test_merged_record_has_sources_tag(self):
        """Merged records are tagged with sources=['onprem', 'intune']."""
        onprem = [_ep("HYBRID-PC", firewall="Enabled")]
        cloud = [_ep("hybrid-pc", metadata={"compliance": "compliant"})]
        result = self.merge(onprem, cloud)
        merged = result[0]
        self.assertEqual(merged.metadata.get("sources"), ["onprem", "intune"])

    def test_merged_record_preserves_intune_metadata(self):
        """The Intune record's metadata is nested under metadata['intune']
        so compliance state, encryption status, etc. are not lost."""
        cloud_meta = {"compliance": "compliant", "encryption": "encrypted"}
        onprem = [_ep("HYBRID-PC", firewall="Enabled", metadata={"domain": "corp"})]
        cloud = [_ep("hybrid-pc", metadata=cloud_meta)]
        result = self.merge(onprem, cloud)
        merged = result[0]
        self.assertEqual(merged.metadata["intune"], cloud_meta)

    def test_merged_record_preserves_original_onprem_metadata(self):
        """Pre-existing on-prem metadata keys survive the merge."""
        onprem_meta = {"domain": "corp.local", "ou": "Workstations"}
        onprem = [_ep("HYBRID-PC", firewall="Enabled", metadata=onprem_meta)]
        cloud = [_ep("hybrid-pc", metadata={"compliance": "compliant"})]
        result = self.merge(onprem, cloud)
        merged = result[0]
        self.assertEqual(merged.metadata["domain"], "corp.local")
        self.assertEqual(merged.metadata["ou"], "Workstations")

    def test_merge_uses_dataclasses_replace(self):
        """The merge must use dataclasses.replace to copy ALL fields from
        the on-prem record, not name them explicitly — otherwise any field
        added to Endpoint later would be silently dropped for hybrid devices
        only (the original bug this was fixed for)."""
        # We can't easily verify replace() was used, but we CAN verify that
        # ALL Endpoint fields from the on-prem record survive the merge.
        onprem = [Endpoint(
            hostname="HYBRID",
            ip_address="192.168.1.50",
            os_version="Windows 11 Enterprise",
            installed_updates=["KB9999"],
            security_products=["Windows Defender", "CrowdStrike"],
            firewall_status="Enabled",
            antivirus_status="Active",
            metadata={"original": True},
        )]
        cloud = [_ep("hybrid", metadata={"cloud_field": "cloud_val"})]
        result = self.merge(onprem, cloud)
        merged = result[0]
        # Every non-metadata field from the on-prem record should survive
        self.assertEqual(merged.hostname, "HYBRID")
        self.assertEqual(merged.ip_address, "192.168.1.50")
        self.assertEqual(merged.os_version, "Windows 11 Enterprise")
        self.assertEqual(merged.installed_updates, ["KB9999"])
        self.assertEqual(merged.security_products, ["Windows Defender", "CrowdStrike"])
        self.assertEqual(merged.firewall_status, "Enabled")
        self.assertEqual(merged.antivirus_status, "Active")

    # -- multiple Intune records for same hostname --------------------------

    def test_multiple_intune_records_first_merged_rest_kept(self):
        """When multiple Intune records share a hostname (re-enrollment
        after re-image), only the first is merged with the on-prem record;
        the rest pass through as separate endpoints."""
        onprem = [_ep("RE-IMAGED", firewall="Enabled")]
        cloud = [
            _ep("re-imaged", metadata={"enrollment": "current"}),
            _ep("re-imaged", metadata={"enrollment": "stale"}),
        ]
        result = self.merge(onprem, cloud)
        # 1 merged + 1 unmerged stale record = 2 total
        self.assertEqual(len(result), 2)
        # The merged one should have the sources tag
        merged = [ep for ep in result if ep.metadata.get("sources") == ["onprem", "intune"]]
        self.assertEqual(len(merged), 1)
        # And the Intune data from the FIRST cloud record
        self.assertEqual(merged[0].metadata["intune"]["enrollment"], "current")

    # -- does not mutate originals ------------------------------------------

    def test_original_lists_not_mutated(self):
        """The merge must not mutate the input lists."""
        onprem = [_ep("PC-A", firewall="Enabled")]
        cloud = [_ep("pc-a", metadata={"x": 1})]
        onprem_copy = list(onprem)
        cloud_copy = list(cloud)
        self.merge(onprem, cloud)
        self.assertEqual(len(onprem), len(onprem_copy))
        self.assertEqual(len(cloud), len(cloud_copy))

    # -- count arithmetic ---------------------------------------------------

    def test_merged_count_arithmetic(self):
        """The orchestrator computes merged_count as
        len(onprem) + len(cloud) - len(result). Verify this is correct."""
        onprem = [_ep("A", firewall="Enabled"), _ep("B", firewall="Enabled")]
        cloud = [_ep("a", metadata={"x": 1}), _ep("C", metadata={"y": 2})]
        result = self.merge(onprem, cloud)
        merged_count = len(onprem) + len(cloud) - len(result)
        # A matched, B didn't, C is cloud-only: 2+2-3 = 1
        self.assertEqual(merged_count, 1)
        self.assertEqual(len(result), 3)


# ===================================================================
# 2. apply_asset_scope
# ===================================================================

class TestApplyAssetScope(unittest.TestCase):
    """Tests for apply_asset_scope — CMMC asset categorization applied to
    a real ArtifactCollection after collection is complete."""

    # -- Out-of-Scope removal -----------------------------------------------

    def test_out_of_scope_endpoints_removed(self):
        """Endpoints categorized as out_of_scope must be physically removed
        from the collection, not just tagged."""
        collection = ArtifactCollection(
            endpoints=[_ep("PRINTER-01"), _ep("WORKSTATION-01")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "PRINTER-01",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Network printer, no CUI")],
        )
        result = apply_asset_scope(collection, scope)
        # PRINTER-01 removed from collection in-place
        self.assertEqual(len(collection.endpoints), 1)
        self.assertEqual(collection.endpoints[0].hostname, "WORKSTATION-01")
        # Tracked in the result
        self.assertIn("PRINTER-01", result.excluded_endpoints)

    def test_out_of_scope_users_removed(self):
        """Users categorized as out_of_scope must be removed from ad_objects."""
        collection = ArtifactCollection(
            ad_objects=[
                _user("guest@contoso.com"),
                _user("admin@contoso.com"),
                _group("CN=Domain Admins"),  # groups are not categorized
            ],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("user", "guest@contoso.com",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Guest account")],
        )
        result = apply_asset_scope(collection, scope)
        # guest removed, admin + group remain
        self.assertEqual(len(collection.ad_objects), 2)
        dns = [o.distinguished_name for o in collection.ad_objects]
        self.assertNotIn("guest@contoso.com", dns)
        self.assertIn("admin@contoso.com", dns)
        self.assertIn("CN=Domain Admins", dns)
        self.assertIn("guest@contoso.com", result.excluded_users)

    # -- CRMA/Specialized tagging -------------------------------------------

    def test_crma_endpoint_tagged_not_removed(self):
        """CRMA endpoints stay in the collection but are tagged in metadata
        so the scorer can exclude them."""
        collection = ArtifactCollection(
            endpoints=[_ep("CONTRACTOR-PC"), _ep("MAIN-PC")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "CONTRACTOR-PC",
                                        AssetCategory.CRMA,
                                        "Limited-access contractor device")],
        )
        result = apply_asset_scope(collection, scope)
        # Both still present
        self.assertEqual(len(collection.endpoints), 2)
        contractor = [ep for ep in collection.endpoints if ep.hostname == "CONTRACTOR-PC"][0]
        self.assertEqual(contractor.metadata["asset_category"], "crma")
        self.assertEqual(contractor.metadata["asset_category_reason"],
                         "Limited-access contractor device")
        # Tracked as documented
        self.assertIn("CONTRACTOR-PC", result.documented_endpoints)

    def test_specialized_user_tagged_not_removed(self):
        """Specialized users stay in ad_objects but are tagged."""
        collection = ArtifactCollection(
            ad_objects=[_user("iot-service@contoso.com")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("user", "iot-service@contoso.com",
                                        AssetCategory.SPECIALIZED,
                                        "IoT monitoring service account")],
        )
        result = apply_asset_scope(collection, scope)
        self.assertEqual(len(collection.ad_objects), 1)
        user = collection.ad_objects[0]
        self.assertEqual(user.attributes["asset_category"], "specialized")
        self.assertIn("iot-service@contoso.com", result.documented_users)

    # -- groups are never categorized ---------------------------------------

    def test_groups_always_pass_through(self):
        """Groups (object_class != 'user') are never subject to scope
        categorization — only users and endpoints are."""
        collection = ArtifactCollection(
            ad_objects=[_group("CN=Domain Admins")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("user", "CN=Domain Admins",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Test — should not match groups")],
        )
        result = apply_asset_scope(collection, scope)
        # Group should survive — not removed
        self.assertEqual(len(collection.ad_objects), 1)

    # -- unmatched exception detection --------------------------------------

    def test_unmatched_exceptions_flagged(self):
        """Exceptions that don't match any collected device/user should be
        reported — this catches typos and stale config entries."""
        collection = ArtifactCollection(
            endpoints=[_ep("REAL-PC")],
            ad_objects=[_user("real@contoso.com")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[
                AssetException("hostname", "TYPO-PC",
                               AssetCategory.OUT_OF_SCOPE, "Doesn't exist"),
                AssetException("user", "gone@contoso.com",
                               AssetCategory.CRMA, "Decommissioned"),
            ],
        )
        result = apply_asset_scope(collection, scope)
        self.assertEqual(len(result.unmatched_exceptions), 2)
        unmatched_ids = {e.identifier for e in result.unmatched_exceptions}
        self.assertEqual(unmatched_ids, {"TYPO-PC", "gone@contoso.com"})

    def test_matched_exception_not_flagged_as_unmatched(self):
        """An exception that DOES match a collected item should NOT appear
        in unmatched_exceptions."""
        collection = ArtifactCollection(
            endpoints=[_ep("PRINTER-01")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "PRINTER-01",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Printer")],
        )
        result = apply_asset_scope(collection, scope)
        self.assertEqual(len(result.unmatched_exceptions), 0)

    # -- case-insensitive matching ------------------------------------------

    def test_exception_matching_case_insensitive(self):
        """Exception identifiers match case-insensitively — 'printer-01'
        in config should match 'PRINTER-01' in collected data."""
        collection = ArtifactCollection(
            endpoints=[_ep("PRINTER-01")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "printer-01",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Printer")],
        )
        result = apply_asset_scope(collection, scope)
        self.assertEqual(len(collection.endpoints), 0)
        self.assertIn("PRINTER-01", result.excluded_endpoints)

    # -- default=out_of_scope rejection -------------------------------------

    def test_default_out_of_scope_rejected(self):
        """Setting default=out_of_scope must raise ValueError — this would
        silently empty the entire collection, producing the most misleading
        artifact this tool could generate."""
        collection = ArtifactCollection(endpoints=[_ep("PC-1")])
        scope = AssetScope(default=AssetCategory.OUT_OF_SCOPE)
        with self.assertRaises(ValueError) as ctx:
            apply_asset_scope(collection, scope)
        self.assertIn("out_of_scope", str(ctx.exception))

    # -- counts in result ---------------------------------------------------

    def test_result_counts_accurate(self):
        """total_endpoints_seen and total_users_seen should reflect the
        collection BEFORE scope filtering, not after."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC-1"), _ep("PC-2"), _ep("PC-3")],
            ad_objects=[_user("a@co.com"), _user("b@co.com"), _group("CN=G")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "PC-3",
                                        AssetCategory.OUT_OF_SCOPE,
                                        "Test device")],
        )
        result = apply_asset_scope(collection, scope)
        self.assertEqual(result.total_endpoints_seen, 3)  # pre-removal count
        self.assertEqual(result.total_users_seen, 2)      # groups don't count
        self.assertEqual(len(collection.endpoints), 2)     # post-removal

    # -- mutates in place ---------------------------------------------------

    def test_mutates_collection_in_place(self):
        """apply_asset_scope mutates the collection directly — the caller's
        reference reflects the changes without needing reassignment."""
        collection = ArtifactCollection(
            endpoints=[_ep("KEEP"), _ep("DROP")],
        )
        scope = AssetScope(
            default=AssetCategory.CUI_ASSET,
            exceptions=[AssetException("hostname", "DROP",
                                        AssetCategory.OUT_OF_SCOPE, "Test")],
        )
        apply_asset_scope(collection, scope)
        self.assertEqual(len(collection.endpoints), 1)
        self.assertEqual(collection.endpoints[0].hostname, "KEEP")

    # -- default CRMA applies to all unexcepted items -----------------------

    def test_default_crma_tags_all_unexcepted(self):
        """When the default category is CRMA, every endpoint/user without
        an explicit exception gets tagged as CRMA (documented, not scored)."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC-A"), _ep("PC-B")],
            ad_objects=[_user("user1@co.com")],
        )
        scope = AssetScope(
            default=AssetCategory.CRMA,
            exceptions=[AssetException("hostname", "PC-B",
                                        AssetCategory.CUI_ASSET,
                                        "This one IS fully in scope")],
        )
        result = apply_asset_scope(collection, scope)
        # PC-A gets the CRMA default, PC-B is excepted to CUI_ASSET
        pc_a = [ep for ep in collection.endpoints if ep.hostname == "PC-A"][0]
        pc_b = [ep for ep in collection.endpoints if ep.hostname == "PC-B"][0]
        self.assertEqual(pc_a.metadata.get("asset_category"), "crma")
        self.assertNotIn("asset_category", pc_b.metadata)
        # user1 also gets CRMA default
        u = collection.ad_objects[0]
        self.assertEqual(u.attributes.get("asset_category"), "crma")


# ===================================================================
# 3. ComplianceScorer — None returns, renormalization, exclusions
# ===================================================================

class TestScorerNoneReturns(unittest.TestCase):
    """Each scoring dimension should return None when it has no applicable
    data, NOT 0 or 100 — 'we don't know' is different from 'failed' and
    different from 'passed'."""

    def test_firewall_none_with_no_onprem_or_cloud_firewall(self):
        """No on-prem endpoints AND no cloud firewall status → None."""
        collection = ArtifactCollection(endpoints=[])
        self.assertIsNone(ComplianceScorer._score_firewall(collection))

    def test_firewall_none_cloud_only_no_firewall_metadata(self):
        """Cloud endpoints exist but have no cloud_firewall_status → None
        for this dimension (not 0)."""
        collection = ArtifactCollection(
            endpoints=[_ep("CLOUD-PC", metadata={"source": "intune"})],
        )
        self.assertIsNone(ComplianceScorer._score_firewall(collection))

    def test_antivirus_none_with_no_data(self):
        """No endpoints with antivirus_status → None."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC1")],  # antivirus_status defaults to None
        )
        self.assertIsNone(ComplianceScorer._score_antivirus(collection))

    def test_updates_none_with_no_onprem(self):
        """No on-prem endpoints (firewall_status is None) → None for updates."""
        collection = ArtifactCollection(
            endpoints=[_ep("CLOUD-PC", metadata={"source": "intune"})],
        )
        self.assertIsNone(ComplianceScorer._score_updates(collection))

    def test_policies_none_with_no_policies(self):
        self.assertIsNone(ComplianceScorer._score_policies(ArtifactCollection()))

    def test_policies_none_with_only_group_policy(self):
        """Group Policy entries are informational (pass/fail not determinable)
        and should not contribute — if they're the ONLY policies, dimension
        returns None."""
        collection = ArtifactCollection(
            policies=[_policy(ptype="Group Policy", status="Enabled")],
        )
        self.assertIsNone(ComplianceScorer._score_policies(collection))

    def test_event_logging_none_with_no_events(self):
        """No events → None (could mean 'logging is broken', can't tell)."""
        self.assertIsNone(
            ComplianceScorer._score_event_logging(ArtifactCollection())
        )

    def test_ad_security_none_with_no_stale_info(self):
        """Users exist but none have isStale attribute → None."""
        collection = ArtifactCollection(
            ad_objects=[_user("user1@co.com", is_stale=None)],
        )
        self.assertIsNone(ComplianceScorer._score_ad_security(collection))


class TestScorerRenormalization(unittest.TestCase):
    """The overall score must renormalize weights across ONLY the dimensions
    that returned data, not penalize a tenant for dimensions that don't
    apply to them."""

    def test_cloud_only_renormalizes_without_onprem_dimensions(self):
        """A cloud-only tenant with no on-prem endpoints should score based
        only on the dimensions that have data, not get zeros for firewall/
        antivirus/updates."""
        # Only ad_security and event_logging have data here
        collection = ArtifactCollection(
            ad_objects=[_user("u1@co.com", is_stale=False),
                        _user("u2@co.com", is_stale=False)],
            security_events=[_event("Information")] * 10,
        )
        dims = ComplianceScorer._all_dimension_scores(collection)
        # firewall, antivirus, updates should all be None
        self.assertIsNone(dims["firewall"])
        self.assertIsNone(dims["antivirus"])
        self.assertIsNone(dims["updates"])
        # The ones with data should NOT be None
        self.assertIsNotNone(dims["ad_security"])
        self.assertIsNotNone(dims["event_logging"])

        score = ComplianceScorer.calculate_overall_score(collection)
        # Both active dimensions score 100 here, so overall should be 100
        self.assertEqual(score, 100)

    def test_single_dimension_renormalizes_to_full_weight(self):
        """If only one dimension has data, overall score == that dimension's
        score, regardless of its weight (the weight becomes 100% after
        renormalization)."""
        # Use policies only — no endpoints (avoids firewall/antivirus/updates
        # all triggering together since they share the on-prem signal).
        collection = ArtifactCollection(
            policies=[
                _policy(name="ClearTextPassword", status="Disabled"),  # pass
                _policy(name="ClearTextPassword", status="Enabled"),   # fail
            ],
        )
        policy_score = ComplianceScorer._score_policies(collection)
        self.assertEqual(policy_score, 50)
        overall = ComplianceScorer.calculate_overall_score(collection)
        self.assertEqual(overall, 50)

    def test_all_dimensions_assessed_no_renormalization(self):
        """When all 6 dimensions have data, the overall score is the
        standard weighted average with no renormalization needed."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC1", firewall="Enabled", antivirus="Active",
                           updates=["KB1"])],
            policies=[_policy(name="ClearTextPassword", status="Disabled")],
            security_events=[_event("Information")] * 10,
            ad_objects=[_user("u@co.com", is_stale=False)],
        )
        dims = ComplianceScorer._all_dimension_scores(collection)
        # Every dimension should have data
        for dim, val in dims.items():
            self.assertIsNotNone(val, f"{dim} should have data but returned None")

    def test_no_dimensions_returns_zero(self):
        """If NO dimensions have data, score is 0 (not an error)."""
        score = ComplianceScorer.calculate_overall_score(ArtifactCollection())
        self.assertEqual(score, 0)


class TestScorerCoverage(unittest.TestCase):
    """calculate_coverage must agree with the score on which dimensions
    were assessed, and report weight-based coverage."""

    def test_coverage_weight_based(self):
        """Coverage percentage is weight-based, not count-based."""
        # On-prem endpoints trigger firewall (15), antivirus (15), AND
        # updates (15) — they share the firewall_status-is-not-None signal.
        # So this gives us 3 dimensions = 45/100 weight.
        collection = ArtifactCollection(
            endpoints=[_ep("PC1", firewall="Enabled", antivirus="Active")],
        )
        coverage = ComplianceScorer.calculate_coverage(collection)
        # firewall(15) + antivirus(15) + updates(15) = 45/100 = 45%
        self.assertEqual(coverage["assessed_weight_pct"], 45)
        self.assertEqual(coverage["assessed_count"], 3)
        self.assertEqual(coverage["total_count"], 6)

    def test_coverage_agrees_with_score(self):
        """assessed_dimensions in coverage must exactly match which
        dimensions returned non-None in the score calculation."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC1", firewall="Enabled")],
            security_events=[_event("Information")],
        )
        dims = ComplianceScorer._all_dimension_scores(collection)
        expected_assessed = {k for k, v in dims.items() if v is not None}
        coverage = ComplianceScorer.calculate_coverage(collection)
        self.assertEqual(set(coverage["assessed_dimensions"]), expected_assessed)

    def test_full_coverage_100_percent(self):
        """All dimensions assessed → 100%."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC1", firewall="Enabled", antivirus="Active",
                           updates=["KB1"])],
            policies=[_policy(name="ClearTextPassword", status="Disabled")],
            security_events=[_event("Information")],
            ad_objects=[_user("u@co.com", is_stale=False)],
        )
        coverage = ComplianceScorer.calculate_coverage(collection)
        self.assertEqual(coverage["assessed_weight_pct"], 100)


class TestScorerCRMAExclusion(unittest.TestCase):
    """Endpoints/users tagged as CRMA or Specialized by apply_asset_scope
    must be excluded from scoring — they appear in report tables but don't
    contribute to the compliance number."""

    def test_crma_endpoint_excluded_from_firewall_score(self):
        """A CRMA-tagged on-prem endpoint should not count toward the
        firewall dimension."""
        crma_ep = _ep("CRMA-PC", firewall="Disabled",
                       metadata={"asset_category": "crma"})
        good_ep = _ep("GOOD-PC", firewall="Enabled")
        collection = ArtifactCollection(endpoints=[crma_ep, good_ep])
        score = ComplianceScorer._score_firewall(collection)
        # Only GOOD-PC counts → 100, not 50
        self.assertEqual(score, 100)

    def test_specialized_endpoint_excluded_from_antivirus(self):
        specialized = _ep("IOT-DEVICE", antivirus="Inactive",
                          metadata={"asset_category": "specialized"})
        good = _ep("MAIN-PC", antivirus="Active")
        collection = ArtifactCollection(endpoints=[specialized, good])
        score = ComplianceScorer._score_antivirus(collection)
        self.assertEqual(score, 100)

    def test_crma_user_excluded_from_ad_security(self):
        """A CRMA-tagged user should not affect the ad_security score."""
        crma_user = _user("contractor@co.com", is_stale=True,
                          category="crma")
        good_user = _user("employee@co.com", is_stale=False)
        collection = ArtifactCollection(ad_objects=[crma_user, good_user])
        score = ComplianceScorer._score_ad_security(collection)
        # Only good_user counts → 100
        self.assertEqual(score, 100)

    def test_all_crma_returns_none(self):
        """If ALL endpoints/users are CRMA, the dimension returns None
        (no scoreable data), not 0 or 100."""
        collection = ArtifactCollection(
            endpoints=[_ep("PC1", firewall="Enabled",
                           metadata={"asset_category": "crma"})],
        )
        self.assertIsNone(ComplianceScorer._score_firewall(collection))

    def test_cui_and_spa_endpoints_scored_normally(self):
        """CUI Asset (the default) and SPA endpoints ARE scored — only
        CRMA and Specialized are excluded."""
        # SPA endpoint — should still be scored
        spa_ep = _ep("SPA-PC", firewall="Enabled",
                      metadata={"asset_category": "spa"})
        # CUI endpoint (no tag = default = CUI)
        cui_ep = _ep("CUI-PC", firewall="Disabled")
        collection = ArtifactCollection(endpoints=[spa_ep, cui_ep])
        score = ComplianceScorer._score_firewall(collection)
        # SPA scores as on-prem (firewall_status is set), CUI too → 50
        self.assertEqual(score, 50)


class TestScorerPolicyRules(unittest.TestCase):
    """Verify specific policy evaluation rules — these encode real security
    semantics, not generic pass/fail."""

    def test_cleartext_password_disabled_is_pass(self):
        """ClearTextPassword is security-inverted: Disabled = secure."""
        p = _policy(name="ClearTextPassword", status="Disabled")
        self.assertTrue(ComplianceScorer._policy_passes(p))

    def test_cleartext_password_enabled_is_fail(self):
        p = _policy(name="ClearTextPassword", status="Enabled")
        self.assertFalse(ComplianceScorer._policy_passes(p))

    def test_min_password_length_threshold(self):
        """MinimumPasswordLength must be >= 14."""
        self.assertTrue(ComplianceScorer._policy_passes(
            _policy(name="MinimumPasswordLength", value="14")))
        self.assertTrue(ComplianceScorer._policy_passes(
            _policy(name="MinimumPasswordLength", value="20")))
        self.assertFalse(ComplianceScorer._policy_passes(
            _policy(name="MinimumPasswordLength", value="8")))

    def test_lockout_bad_count_range(self):
        """LockoutBadCount must be 1-5 (0 = no lockout = fail)."""
        self.assertTrue(ComplianceScorer._policy_passes(
            _policy(name="LockoutBadCount", value="3")))
        self.assertFalse(ComplianceScorer._policy_passes(
            _policy(name="LockoutBadCount", value="0")))
        self.assertFalse(ComplianceScorer._policy_passes(
            _policy(name="LockoutBadCount", value="10")))

    def test_audit_policy_no_auditing_is_fail(self):
        """Audit policies with 'No Auditing' status should fail."""
        p = _policy(ptype="Audit Policy", status="No Auditing")
        self.assertFalse(ComplianceScorer._policy_passes(p))

    def test_audit_policy_success_and_failure_is_pass(self):
        p = _policy(ptype="Audit Policy", status="Success and Failure")
        self.assertTrue(ComplianceScorer._policy_passes(p))

    def test_group_policy_returns_none(self):
        """Group Policy entries are informational — returns None (skip)."""
        p = _policy(ptype="Group Policy", status="Applied")
        self.assertIsNone(ComplianceScorer._policy_passes(p))


class TestScorerCloudFirewall(unittest.TestCase):
    """The firewall dimension blends on-prem and cloud firewall data."""

    def test_cloud_firewall_enabled_scores_100(self):
        """Cloud endpoint with cloud_firewall_status='Enabled' should
        score 100 for that device."""
        ep = _ep("CLOUD-PC", metadata={"cloud_firewall_status": "Enabled"})
        collection = ArtifactCollection(endpoints=[ep])
        self.assertEqual(ComplianceScorer._score_firewall(collection), 100)

    def test_cloud_firewall_disabled_scores_0(self):
        ep = _ep("CLOUD-PC", metadata={"cloud_firewall_status": "Disabled"})
        collection = ArtifactCollection(endpoints=[ep])
        self.assertEqual(ComplianceScorer._score_firewall(collection), 0)

    def test_blended_onprem_and_cloud(self):
        """Mixed on-prem and cloud endpoints average together."""
        onprem = _ep("ONPREM", firewall="Enabled")  # scores 100
        cloud = _ep("CLOUD", metadata={"cloud_firewall_status": "Disabled"})  # scores 0
        collection = ArtifactCollection(endpoints=[onprem, cloud])
        self.assertEqual(ComplianceScorer._score_firewall(collection), 50)

    def test_unrecognized_cloud_status_excluded(self):
        """Unknown cloud firewall statuses are excluded from scoring, not
        scored as 0."""
        good = _ep("CLOUD-A", metadata={"cloud_firewall_status": "Enabled"})
        unknown = _ep("CLOUD-B", metadata={"cloud_firewall_status": "Limited"})
        collection = ArtifactCollection(endpoints=[good, unknown])
        # Only good counts → 100, not 50
        self.assertEqual(ComplianceScorer._score_firewall(collection), 100)


class TestScorerEventLogging(unittest.TestCase):
    """Event logging score is ratio-based: more critical/error events
    relative to total → lower score."""

    def test_all_info_events_scores_100(self):
        collection = ArtifactCollection(
            security_events=[_event("Information")] * 10,
        )
        self.assertEqual(ComplianceScorer._score_event_logging(collection), 100)

    def test_all_critical_events_scores_0(self):
        collection = ArtifactCollection(
            security_events=[_event("Critical")] * 10,
        )
        self.assertEqual(ComplianceScorer._score_event_logging(collection), 0)

    def test_mixed_events_scores_proportionally(self):
        events = [_event("Information")] * 8 + [_event("Critical")] * 2
        collection = ArtifactCollection(security_events=events)
        score = ComplianceScorer._score_event_logging(collection)
        # 2/10 = 20% critical → 100 - 20 = 80
        self.assertEqual(score, 80)

    def test_error_events_count_as_critical(self):
        """Both 'Critical' and 'Error' events are counted as bad."""
        events = [_event("Information")] * 5 + [_event("Error")] * 5
        collection = ArtifactCollection(security_events=events)
        score = ComplianceScorer._score_event_logging(collection)
        self.assertEqual(score, 50)


class TestScorerADSecurity(unittest.TestCase):
    """AD security scores accounts where disabled OR not-stale = healthy."""

    def test_all_healthy_active(self):
        """Active, not-stale users → 100."""
        collection = ArtifactCollection(
            ad_objects=[_user("a@co.com", is_stale=False),
                        _user("b@co.com", is_stale=False)],
        )
        self.assertEqual(ComplianceScorer._score_ad_security(collection), 100)

    def test_stale_and_active_account(self):
        """A stale, enabled account is the risk signal — scores unhealthy."""
        collection = ArtifactCollection(
            ad_objects=[_user("ok@co.com", is_stale=False),
                        _user("stale@co.com", is_stale=True)],
        )
        score = ComplianceScorer._score_ad_security(collection)
        # 1/2 healthy = 50
        self.assertEqual(score, 50)

    def test_disabled_stale_is_healthy(self):
        """A disabled account is healthy even if also stale — the risk is
        an enabled-but-abandoned account, not a disabled one."""
        collection = ArtifactCollection(
            ad_objects=[_user("disabled@co.com", is_stale=True, disabled=True)],
        )
        self.assertEqual(ComplianceScorer._score_ad_security(collection), 100)

    def test_groups_ignored(self):
        """Groups should not affect the AD security score."""
        collection = ArtifactCollection(
            ad_objects=[
                _user("u@co.com", is_stale=False),
                _group("CN=Domain Admins"),
            ],
        )
        self.assertEqual(ComplianceScorer._score_ad_security(collection), 100)


# ===================================================================
# 4. CSV exception loading (asset_scope.load_exceptions_csv)
# ===================================================================

class TestLoadExceptionsCsv(unittest.TestCase):
    """Tests for load_exceptions_csv — the Excel-friendly CSV importer."""

    def _write_csv(self, content):
        """Write a temporary CSV and return its path."""
        import tempfile
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False,
                                        encoding="utf-8-sig", newline="")
        f.write(content)
        f.close()
        return f.name

    def test_valid_csv(self):
        path = self._write_csv(
            "identifier_type,identifier,category,reason\n"
            "hostname,PRINTER-01,out_of_scope,\"Network printer\"\n"
            "user,guest@co.com,crma,\"Guest account\"\n"
        )
        try:
            exceptions = load_exceptions_csv(path)
            self.assertEqual(len(exceptions), 2)
            self.assertEqual(exceptions[0].identifier, "PRINTER-01")
            self.assertEqual(exceptions[0].category, AssetCategory.OUT_OF_SCOPE)
            self.assertEqual(exceptions[1].identifier, "guest@co.com")
            self.assertEqual(exceptions[1].category, AssetCategory.CRMA)
        finally:
            os.unlink(path)

    def test_missing_column_raises(self):
        path = self._write_csv("identifier_type,identifier,category\nhostname,PC1,crma\n")
        try:
            with self.assertRaises(ValueError) as ctx:
                load_exceptions_csv(path)
            self.assertIn("reason", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_invalid_category_raises(self):
        path = self._write_csv(
            "identifier_type,identifier,category,reason\n"
            "hostname,PC1,bogus,\"test\"\n"
        )
        try:
            with self.assertRaises(ValueError) as ctx:
                load_exceptions_csv(path)
            self.assertIn("bogus", str(ctx.exception))
            self.assertIn("row 2", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_empty_reason_raises(self):
        path = self._write_csv(
            "identifier_type,identifier,category,reason\n"
            "hostname,PC1,crma,\n"
        )
        try:
            with self.assertRaises(ValueError) as ctx:
                load_exceptions_csv(path)
            self.assertIn("reason", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_file_not_found_raises(self):
        with self.assertRaises(ValueError):
            load_exceptions_csv("/nonexistent/path.csv")


if __name__ == "__main__":
    unittest.main()
