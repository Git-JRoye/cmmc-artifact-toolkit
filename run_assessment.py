"""General-purpose assessment runner.

Unlike pilot_test.py (which hardcodes ONE pilot environment directly in
Python source, by design, for initial validation only), this script reads
tenant configuration from a YAML file — see tenants.example.yaml for the
format. Nothing about this file is specific to any one business; every
real client's identifiers live in your own tenants.yaml (gitignored), never
in this codebase.

Usage:

    # First time: copy the example config and fill in your real client details
    cp tenants.example.yaml tenants.yaml

    # Run every configured tenant
    python run_assessment.py --all

    # Run just one tenant by its tenant_key
    python run_assessment.py --tenant acme

    # List configured tenants without running anything
    python run_assessment.py --list

    # Use a config file at a different path
    python run_assessment.py --all --config /path/to/tenants.yaml

Secrets: the default secret resolver reads environment variables named
exactly as each tenant's secret_ref value says (e.g. secret_ref
"ACME_GRAPH_CLIENT_SECRET" -> $env:ACME_GRAPH_CLIENT_SECRET). This is a
reasonable default for a single operator running this locally, same as
pilot_test.py's resolver — but it is NOT a real secrets-management solution.
For anything beyond a single-operator setup (an MSP with many clients,
several people running assessments), replace build_secret_resolver() below
with a real vault/secret-store lookup before this touches real client data
at scale.
"""

import argparse
import logging
import os
import sys

sys.path.insert(0, "src")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from cmmc_gatherer.orchestrator import TenantOrchestrator  # noqa: E402
from cmmc_gatherer.tenant_config_loader import TenantConfigError, load_tenant_profiles  # noqa: E402
from cmmc_gatherer.utils.compliance import ComplianceScorer  # noqa: E402
from cmmc_gatherer.exporters.msp_report_exporter import MSPReportExporter  # noqa: E402

logger = logging.getLogger(__name__)


def build_secret_resolver():
    """Default resolver: environment variables, looked up by the secret_ref
    name each tenant's config entry specifies. See this file's module
    docstring for why this isn't sufficient beyond a single-operator setup.
    """
    def resolve(secret_ref: str) -> str:
        value = os.environ.get(secret_ref)
        if value is None:
            raise ValueError(
                f"No environment variable set for secret_ref='{secret_ref}'. "
                f"Set it before running, e.g.: $env:{secret_ref}='...'"
            )
        return value
    return resolve


def summarize(result) -> None:
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
    if result.errors:
        print(f"  ERRORS ({len(result.errors)}):")
        for e in result.errors:
            print(f"    - {e}")
    else:
        print("  No errors reported.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CMMC evidence collection for one or more configured tenants.")
    parser.add_argument("--config", default="tenants.yaml",
                         help="Path to the tenant config file (default: tenants.yaml)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Run every tenant in the config file")
    group.add_argument("--tenant", metavar="TENANT_KEY", help="Run only the named tenant")
    group.add_argument("--list", action="store_true", help="List configured tenants and exit")
    args = parser.parse_args()

    try:
        profiles = load_tenant_profiles(args.config)
    except TenantConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 1

    if args.list:
        print(f"{len(profiles)} tenant(s) configured in {args.config}:")
        for p in profiles:
            planes = "+".join(pl.value for pl in p.planes)
            print(f"  {p.tenant_key:20s} {p.display_name:30s} [{planes}]")
        return 0

    if args.tenant:
        matches = [p for p in profiles if p.tenant_key == args.tenant]
        if not matches:
            available = ", ".join(p.tenant_key for p in profiles)
            print(f"No tenant with tenant_key '{args.tenant}' found in {args.config}. "
                  f"Available: {available}", file=sys.stderr)
            return 1
        profiles = matches

    orchestrator = TenantOrchestrator(secret_resolver=build_secret_resolver())
    results = orchestrator.run_all(profiles)

    for result in results.values():
        summarize(result)

    for result in results.values():
        out_path = f"report_{result.tenant_key}.html"
        MSPReportExporter().export(
            result.collection, out_path,
            customer_name=result.display_name,
            assessment_id=f"CMMC-{result.tenant_key.upper()}",
        )
        print(f"\nReport written: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
