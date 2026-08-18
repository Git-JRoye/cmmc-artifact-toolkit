"""Run CMMC assessments for all clients defined in tenants.yaml.

This is the production-oriented replacement for pilot_test.py — instead of
hardcoding profiles in Python, it reads them from tenants.yaml so you can
add a new client with 3 lines of YAML and zero code changes.

Usage:
    # Set your app secret (once per session):
    $env:TENGUARD_GRAPH_CLIENT_SECRET = "your-secret-value"

    # Run all clients:
    python run_assessment.py

    # Run a specific client:
    python run_assessment.py --tenant acme

    # Use a different config file:
    python run_assessment.py --config my_clients.yaml

    # Demo mode (no real environment needed):
    $env:CMMC_DEMO = "1"
    python run_assessment.py
"""

import argparse
import logging
import os
import sys

# Auto-load .env file if present (no extra dependency needed).
# This lets you store MSP_SHARED_APP_SECRET in a .env file in the
# project root instead of setting it manually each PowerShell session.
# .env is already in .gitignore so it won't be committed.
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.isfile(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith("#"):
                continue
            key, _, val = _line.partition("=")
            key, val = key.strip(), val.strip()
            # Strip surrounding quotes if present
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if key and val:
                os.environ.setdefault(key, val)

sys.path.insert(0, "src")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from cmmc_gatherer.tenant_config_loader import load_tenants  # noqa: E402
from cmmc_gatherer.orchestrator import TenantOrchestrator  # noqa: E402
from cmmc_gatherer.utils.compliance import ComplianceScorer  # noqa: E402
from cmmc_gatherer.exporters.msp_report_exporter import MSPReportExporter  # noqa: E402


def secret_resolver(secret_ref: str) -> str:
    """Read secrets from environment variables.

    For production, swap this with a vault/secret-store lookup.
    """
    value = os.environ.get(secret_ref)
    if value is None:
        raise ValueError(
            f"No environment variable set for '{secret_ref}'. "
            f"Set it before running, e.g.: $env:{secret_ref}='...'"
        )
    return value


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


def main():
    parser = argparse.ArgumentParser(
        description="Run CMMC assessments from tenants.yaml"
    )
    parser.add_argument(
        "--config", default="tenants.yaml",
        help="Path to YAML config file (default: tenants.yaml)"
    )
    parser.add_argument(
        "--tenant", default=None,
        help="Run only this tenant_key (default: all)"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Enable demo mode (same as CMMC_DEMO=1)"
    )
    args = parser.parse_args()

    demo = args.demo or bool(int(os.environ.get("CMMC_DEMO", "0")))

    profiles = load_tenants(args.config)

    if args.tenant:
        profiles = [p for p in profiles if p.tenant_key == args.tenant]
        if not profiles:
            print(f"No tenant with key '{args.tenant}' found in {args.config}")
            sys.exit(1)

    print(f"Running assessments for {len(profiles)} client(s)...")

    orchestrator = TenantOrchestrator(secret_resolver=secret_resolver, demo=demo)
    results = orchestrator.run_all(profiles)

    for result in results.values():
        summarize(result)

    for result in results.values():
        out_path = f"report_{result.tenant_key}.html"
        MSPReportExporter().export(
            result.collection, out_path,
            customer_name=result.display_name,
            assessment_id=f"ASSESS-{result.tenant_key.upper()}",
            scope_result=result.scope_result,
            health_log=result.health_log,
        )
        print(f"\nReport written: {out_path}")

    print(f"\nDone — {len(results)} assessment(s) complete.")


if __name__ == "__main__":
    main()
