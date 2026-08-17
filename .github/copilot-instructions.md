<!-- CMMC Artifact Toolkit - AI assistant instructions -->

## What this project is

Evidence collection and CMMC/NIST SP 800-171 compliance scoring across two
collection planes — on-prem Windows/Active Directory (PowerShell + LDAP)
and cloud Entra ID/Intune (Microsoft Graph) — feeding one shared artifact
model, a weighted compliance scorer, a CMMC-practice mapping registry, and
an HTML report exporter. Used both by MSPs assessing multiple client
tenants and by a single organization assessing itself.

This is a fork of `tkhemraj/cmmc` (see `git remote -v` — `upstream`). A
meaningful amount of code under `src/cmmc_gatherer/gatherer.py` and
`src/cmmc_gatherer/cli.py` is **pre-fork upstream code that nobody runs
anymore** — see "What is NOT the real entry point" below before assuming
anything reachable from `CMMCGatherer` reflects current behavior.

## Real entry points

- **`run_assessment.py`** — the actual way this tool is run. Reads
  multi-tenant config from a YAML file (`tenants.yaml`, gitignored;
  `tenants.example.yaml` is the checked-in generic template — Acme,
  Globex, Initech, etc., never real client data), resolves secrets via a
  pluggable `secret_resolver` (default: environment variables, named by
  each tenant's `secret_ref`), and drives `TenantOrchestrator`.
  ```
  python run_assessment.py --config tenants.yaml --list   # validate config only
  python run_assessment.py --tenant acme                  # one tenant
  python run_assessment.py --all                          # every tenant
  ```
- **`pilot_test.py`** — a single hardcoded `TenantProfile` pair
  (on-prem + cloud) for validating against one real test environment
  before trusting the tool against real client data. Even here, the cloud
  tenant's `tenant_id`/`client_id` come from environment variables
  (`PILOT_CLOUD_TENANT_ID`/`PILOT_CLOUD_CLIENT_ID`), not hardcoded source
  — real Azure AD identifiers don't belong in version control even when
  they aren't secrets.

## What is NOT the real entry point

`src/cmmc_gatherer/cli.py` (`cmmc-gatherer collect/report/export`) wraps
`src/cmmc_gatherer/gatherer.py`'s `CMMCGatherer.collect_all()`, which
directly instantiates the four on-prem collectors with **no**
`TenantProfile`, no cloud plane, no `TenantOrchestrator`, no secret
resolution, and no asset scope. It reflects the pre-fork, on-prem-only
architecture. Do not use it as a reference for how collection actually
works, and do not "helpfully" wire new features into it — extend
`TenantOrchestrator` and the collectors it calls instead. (`setup.py` no
longer installs a `cmmc-gatherer` console script for this reason.)

## Architecture

```
src/cmmc_gatherer/
├── collectors/
│   ├── base.py                    # shared CollectorBase interface
│   ├── onprem/                    # Windows / on-prem AD plane (PowerShell + LDAP)
│   │   ├── endpoint_collector.py, ad_collector.py, event_log_collector.py, policy_collector.py
│   └── cloud/                     # Entra ID / Intune plane (Microsoft Graph)
│       ├── entra_identity_collector.py, service_principal_collector.py
│       ├── intune_device_collector.py, intune_rbac_collector.py
│       ├── cloud_event_collector.py, cloud_policy_collector.py
├── cloud/
│   ├── cloud_config.py            # national-cloud registry (commercial/GCC/GCC High/DoD) + TenantProfile
│   └── graph.py                   # Graph auth providers + paged/versioned client
├── models/artifacts.py            # shared artifact types: Endpoint, ADObject, SecurityEvent, Policy
├── asset_scope.py                 # CMMC asset categorization (CUI Asset/SPA/CRMA/Specialized/Out-of-Scope)
├── collection_health.py           # logging.Handler capturing every collector WARNING/ERROR into the report
├── control_mapping.py             # evidence -> CMMC practice registry (DIRECT/SUPPORTING confidence)
├── tenant_config_loader.py        # tenants.yaml -> TenantProfile objects
├── orchestrator.py                # TenantOrchestrator: picks plane(s) per tenant, runs collectors, merges devices
├── utils/compliance.py            # ComplianceScorer — six-dimension weighted scoring
└── exporters/msp_report_exporter.py  # the real HTML report (135KB, one class — known, accepted, not a target for a drive-by refactor)
```

## Conventions that matter — read before editing collectors, the scorer, or the exporter

**Two planes, one model set.** An on-prem endpoint and an Intune-managed
device don't expose the same fields — a centrally managed device has no
local firewall-profile concept, for instance. Cloud collectors map what
genuinely translates into the shared `Endpoint`/`ADObject`/`Policy`
fields and leave the rest `None`; native cloud-only signals (compliance
state, encryption, BitLocker escrow, real-time Defender health, ownership
type, etc.) go into `metadata: Dict[str, Any]`, never into a repurposed
on-prem field. **Never fabricate a value to make the schema line up** — a
field that doesn't apply to a given plane stays `None`, and downstream
code is expected to handle that, not be shielded from it.

**`ep.firewall_status is not None` is the load-bearing "this is
on-prem-shaped data" signal.** The scorer (`ComplianceScorer._onprem_endpoints`),
the exporter (`MSPReportExporter._onprem_endpoints`/`_cloud_endpoints`),
and the findings generator all partition endpoints this way. If you add a
new on-prem-only or cloud-only field, follow the same pattern — don't
invent a second, parallel way to detect which plane an endpoint came from.

**The scorer never guesses.** Any dimension with no applicable data
returns `None` — not `0`, not `100`. `calculate_overall_score()`
renormalizes weights across only the dimensions that had data, so a
cloud-only tenant isn't penalized for a metric (e.g. on-prem patch
presence) that doesn't apply to it. **Every displayed score must be paired
with `calculate_coverage()`** wherever it appears — a score computed from
2 of 6 dimensions must never be presented without also saying so; the
exporter's coverage banner and Scoring Breakdown section exist specifically
for this. Don't add a new place that shows a bare percentage.

**`control_mapping.py` is the single source of truth for evidence →
practice.** Report code (`msp_report_exporter.py`) never hardcodes a
CMMC/NIST practice ID inline — it looks evidence up via
`control_mapping.get_evidence()`/`practices_for_evidence()`/`domain_coverage()`.
Adding a new collector's evidence to the report's control coverage means:
add one `EvidenceMapping` entry here, and one detection line in the
exporter's `_present_evidence_keys()`. Nothing else should need to change.

**DIRECT vs. SUPPORTING is not a vibe — it's one concrete test.** An
Intune compliance-policy *requirement* ("storage encryption is required")
is a different epistemic class from an *observed device state*
("real-time protection is currently running on this device"). Only an
observed, real state on an actual device earns `Confidence.DIRECT`; a
requirement with no confirmed observation is `SUPPORTING` at best. Before
assigning or changing a confidence level, apply the test literally stated
in `control_mapping.py`'s own docstring: *"does this prove something IS
true on a device, or only that something is DEMANDED of it?"* Scoring
logic, DIRECT/SUPPORTING assignments in `control_mapping.py`, and
`asset_scope.py` behavior encode deliberate, previously-litigated
correctness decisions — don't change them as a drive-by; flag it instead.

**Asset categorization is never inferred, only applied as declared.**
`asset_scope.py` implements the CMMC Assessment Guide's 5 categories
(CUI Asset, SPA, CRMA, Specialized, Out-of-Scope). The CMMC guide
requires this to be a defensible human decision — this tool only ever
applies exactly what a tenant's config declares (default: everything is a
CUI Asset, fully assessed). Never add a heuristic that guesses a device's
or user's category from its data.

**Collectors report problems via `logger.warning()`/`logger.error()`,
nothing more.** `CollectionHealthRecorder` (a `logging.Handler` attached
to the `cmmc_gatherer` logger for the duration of one tenant's run in
`orchestrator.run_one()`) captures every WARNING/ERROR automatically and
surfaces it in the report's always-present Collection Health page — no
collector needs to opt into this or call anything special. Isolate a new,
less-verified Graph lookup in its own per-device/per-resource
try/except that logs and continues, rather than folding it into a shared
bulk `$select` — a single bad field in a shared list call has previously
broken an entire device list at once (see the `ownerType` regression noted
in `intune_device_collector.py`).

**Multi-cloud is configuration, not code paths.** `cloud/cloud_config.py`
maps each national cloud (commercial, GCC, GCC High, DoD) to its Graph
endpoint and login authority; `GraphClient` reads a `TenantProfile`'s
`national_cloud` and targets the right one automatically.

## Running things safely while developing

- Syntax/import check (not a test run): `python -m py_compile $(find src -name "*.py") pilot_test.py run_assessment.py`
- Config smoke test (no network, no real credentials): `python run_assessment.py --config tenants.example.yaml --list`
- `tenants.yaml` is gitignored and must never contain real client data.
  `tenants.example.yaml` must stay fully generic (Acme, Globex, Initech,
  Wayne Enterprises, Stark Industries) — no real tenant IDs, client IDs,
  or domain names.
- Generated `report_*.html` files contain real tenant data and are
  gitignored — never add them to a commit.
- Never run `git commit`/`git push` unless explicitly asked.
