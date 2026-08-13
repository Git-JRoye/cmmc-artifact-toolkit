"""Pilot test harness — run this against ONE real test environment before
trusting any of this against actual client data.

This is intentionally NOT how you'd wire secrets in production — it reads
from environment variables via a plain os.environ lookup, which is fine for
a local pilot on your own machine but should never be how a real deployment
resolves client secrets. Swap in a real vault/secret-store lookup before
this touches an actual client.

Usage:
    Fill in ONPREM_PROFILE and/or CLOUD_PROFILE below with your test
    environment's real details, set the corresponding secret as an
    environment variable, then run:

        python pilot_test.py

Set CMMC_DEMO=1 first if you want to sanity-check the harness itself runs
end-to-end before pointing it at anything real:

        set CMMC_DEMO=1   (PowerShell: $env:CMMC_DEMO="1")
        python pilot_test.py
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

ONPREM_PROFILE = None
# ONPREM_PROFILE = TenantProfile(
#     tenant_key="pilot-onprem",
#     display_name="Pilot On-Prem Test Environment",
#     planes=[Plane.ONPREM],
#     domain_config=DomainConfig(
#         domain_controller="dc01.pilot.local",      # your test DC hostname/IP
#         base_dn="DC=pilot,DC=local",                # your test domain's base DN
#         bind_dn="pilot-svc@pilot.local",            # a read-only bind account
#         secret_ref="PILOT_AD_BIND_PASSWORD",        # env var name, not the value
#     ),
# )

CLOUD_PROFILE = TenantProfile(
    tenant_key="tenguard",
    display_name="Tenguard Security",
    national_cloud=NationalCloud.COMMERCIAL,
    planes=[Plane.CLOUD],
    auth_method=AuthMethod.APP_REGISTRATION,
    tenant_id="9f67a082-b275-4e67-9dc5-b1f6f12e7b99",
    client_id="f598a875-1229-4635-b523-8ec93aa6c7a3",
    secret_ref="TENGUARD_GRAPH_CLIENT_SECRET",
)


def summarize(result):
    print(f"\n{'=' * 60}")
    print(f"Tenant: {result.display_name} ({result.tenant_key})")
    print(f"{'=' * 60}")
    c = result.collection
    print(f"  Endpoints:       {len(c.endpoints)}")
    print(f"  AD/identity obj: {len(c.ad_objects)}")
    print(f"  Security events: {len(c.security_events)}")
    print(f"  Policies:        {len(c.policies)}")
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
              "on-prem harness path, or fill in ONPREM_PROFILE/CLOUD_PROFILE above.")
        return

    orchestrator = TenantOrchestrator(secret_resolver=pilot_secret_resolver, demo=demo)
    results = orchestrator.run_all(profiles)

    for result in results.values():
        summarize(result)


if __name__ == "__main__":
    main()
