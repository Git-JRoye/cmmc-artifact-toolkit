"""Pilot test harness — run this against ONE real test environment before
trusting any of this against actual client data.

This is intentionally NOT how you'd wire secrets in production — it reads
from environment variables via a plain os.environ lookup, which is fine for
a local pilot on your own machine but should never be how a real deployment
resolves client secrets. Swap in a real vault/secret-store lookup before
this touches an actual client.

Usage:
    Fill in ONPREM_PROFILE below with your test environment's real details
    if needed (the hostname/display name here aren't sensitive). For
    CLOUD_PROFILE, set the three environment variables below instead of
    editing source — tenant_id/client_id are real Azure AD identifiers for
    your own tenant and don't belong in version control even though they
    aren't secrets on their own:

        $env:PILOT_CLOUD_TENANT_ID = "your-entra-tenant-guid"
        $env:PILOT_CLOUD_CLIENT_ID = "your-app-registration-client-id"
        $env:TENGUARD_GRAPH_CLIENT_SECRET = "the real secret value"
        python pilot_test.py

    Leave PILOT_CLOUD_TENANT_ID/PILOT_CLOUD_CLIENT_ID unset to skip the
    cloud plane for this pilot run — CLOUD_PROFILE becomes None rather than
    failing, same as if you'd commented it out.

Set CMMC_DEMO=1 first if you want to sanity-check the harness itself runs
end-to-end before pointing it at anything real:

        set CMMC_DEMO=1   (PowerShell: $env:CMMC_DEMO="1")
        python pilot_test.py

NOTE: ONPREM_PROFILE and CLOUD_PROFILE below are configured as two SEPARATE
tenant profiles for this pilot, even though they represent the same physical
machine/organization (Johnny's own laptop, scanned locally and also enrolled
in Tenguard's Intune). That's fine for testing each plane independently, but
it means the device de-duplication in orchestrator.py (_merge_endpoints)
never triggers here — merging only happens WITHIN a single TenantProfile
that has both planes=[Plane.ONPREM, Plane.CLOUD] configured, which is how a
real hybrid client would actually be set up in production.
"""

import logging
import os
import sys

sys.path.insert(0, "src")

# Make every collector's logger.info/warning/error actually visible —
# Python's default logging level is WARNING, which would hide most of the
# useful pilot output otherwise.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from cmmc_gatherer.cloud.cloud_config import (  # noqa: E402
    AuthMethod, NationalCloud, Plane, TenantProfile,
)
from cmmc_gatherer.onprem.domain_config import DomainConfig  # noqa: E402
from cmmc_gatherer.orchestrator import TenantOrchestrator  # noqa: E402
from cmmc_gatherer.utils.compliance import ComplianceScorer  # noqa: E402
from cmmc_gatherer.exporters.msp_report_exporter import MSPReportExporter  # noqa: E402


def pilot_secret_resolver(secret_ref: str) -> str:
    """PILOT ONLY. Reads secrets from environment variables by name.

    Replace with a real vault lookup before this ever touches a real client.
    """
    value = os.environ.get(secret_ref)
    if value is None:
        raise ValueError(
            f"No environment variable set for secret_ref='{secret_ref}'. "
            f"Set it before running, e.g.: $env:{secret_ref}='...'"
        )
    return value


# ---------------------------------------------------------------------------
# FILL THESE IN with your real test environment details, or leave commented
# out to skip that plane for this pilot run.
# ---------------------------------------------------------------------------

ONPREM_PROFILE = TenantProfile(
    tenant_key="royepc",
    display_name="ROYEPC (local machine)",
    planes=[Plane.ONPREM],
)

_pilot_tenant_id = os.environ.get("PILOT_CLOUD_TENANT_ID")
_pilot_client_id = os.environ.get("PILOT_CLOUD_CLIENT_ID")

if _pilot_tenant_id and _pilot_client_id:
    CLOUD_PROFILE = TenantProfile(
        tenant_key="tenguard",
        display_name="Tenguard Security",
        national_cloud=NationalCloud.COMMERCIAL,
        planes=[Plane.CLOUD],
        auth_method=AuthMethod.APP_REGISTRATION,
        tenant_id=_pilot_tenant_id,
        client_id=_pilot_client_id,
        secret_ref="TENGUARD_GRAPH_CLIENT_SECRET",
    )
else:
    # Not hardcoded here on purpose (see module docstring) — set
    # PILOT_CLOUD_TENANT_ID / PILOT_CLOUD_CLIENT_ID to exercise this plane.
    CLOUD_PROFILE = None


def summarize(result):
    print(f"\n{'=' * 60}")
    print(f"Tenant: {result.display_name} ({result.tenant_key})")
    print(f"{'=' * 60}")
    c = result.collection
    print(f"  Endpoints:       {len(c.endpoints)}")
    print(f"  AD/identity obj: {len(c.ad_objects)}")
    print(f"  Security events: {len(c.security_events)}")
    print(f"  Policies:        {len(c.policies)}")
    print()
    overall = ComplianceScorer.calculate_overall_score(c)
    coverage = ComplianceScorer.calculate_coverage(c)
    print(f"  Overall compliance score: {overall}/100")
    print(f"  Scoring coverage: {coverage['assessed_count']}/{coverage['total_count']} categories "
          f"({coverage['assessed_weight_pct']}% of scoring weight)"
          + (" — COVERAGE INCOMPLETE" if coverage['assessed_weight_pct'] < 100 else ""))
    for dim in ('firewall', 'antivirus', 'updates', 'policies', 'event_logging', 'ad_security'):
        method = getattr(ComplianceScorer, f'_score_{dim}')
        val = method(c)
        shown = f"{val}/100" if val is not None else "N/A (no applicable data)"
        print(f"    {dim:15s}: {shown}")
    if result.errors:
        print(f"  ERRORS ({len(result.errors)}):")
        for e in result.errors:
            print(f"    - {e}")
    else:
        print("  No errors reported.")

    if c.endpoints:
        print(f"\n  Sample endpoint: {c.endpoints[0]}")
    if c.ad_objects:
        print(f"\n  Sample AD/identity object: {c.ad_objects[0]}")
    if c.security_events:
        print(f"\n  Sample security event: {c.security_events[0]}")
    if c.policies:
        print(f"\n  Sample policy: {c.policies[0]}")


def main():
    demo = bool(int(os.environ.get("CMMC_DEMO", "0")))
    profiles = [p for p in (ONPREM_PROFILE, CLOUD_PROFILE) if p is not None]

    if not profiles and demo:
        # No real profile configured, but CMMC_DEMO=1 was set — actually
        # exercise the orchestrator + on-prem collectors in demo mode rather
        # than short-circuiting here. NOTE: the cloud plane has no demo
        # fallback (Entra/Intune collectors always call real Graph), so this
        # only covers on-prem for now — that's a known, documented gap, not
        # an oversight.
        print("No profiles configured — using a built-in demo profile to "
              "sanity-check the on-prem path end-to-end. (Cloud has no demo "
              "fallback yet, so it isn't covered by this check.)")
        profiles = [TenantProfile(
            tenant_key="demo", display_name="Demo (no real environment)",
            planes=[Plane.ONPREM],
        )]

    if not profiles:
        print("No profiles configured. Either set CMMC_DEMO=1 to test the "
              "on-prem harness path, fill in ONPREM_PROFILE above, or set "
              "PILOT_CLOUD_TENANT_ID/PILOT_CLOUD_CLIENT_ID for the cloud plane.")
        return

    orchestrator = TenantOrchestrator(secret_resolver=pilot_secret_resolver, demo=demo)
    results = orchestrator.run_all(profiles)

    for result in results.values():
        summarize(result)

    for result in results.values():
        out_path = f"report_{result.tenant_key}.html"
        MSPReportExporter().export(
            result.collection, out_path,
            customer_name=result.display_name,
            assessment_id=f"PILOT-{result.tenant_key.upper()}",
            scope_result=result.scope_result,
            health_log=result.health_log,
        )
        print(f"\nReport written: {out_path}")


if __name__ == "__main__":
    main()
