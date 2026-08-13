# CMMC Artifact Toolkit

Evidence collection and CMMC/NIST SP 800-171 compliance scoring for Windows, Active Directory, Entra ID, and Intune environments.

This toolkit gathers the artifacts an assessor actually asks for — endpoint security posture, identity and directory state, device compliance, security event history, and policy configuration — and scores them against CMMC practices, instead of someone manually logging into machines, running PowerShell by hand, and pasting output into a spreadsheet.

It's built to be useful in two settings that need the same underlying data for different reasons:

MSPs / MSSPs assessing multiple client environments and producing client-ready compliance reports.
OSA (Organization Seeking Assessment) engineering teams running continuous internal evidence collection ahead of a C3PAO assessment, or maintaining a defensible SPRS score between annual affirmations.

The architecture supports both: a single-tenant OSA just configures one profile; an MSP configures one per client.

Status — read this before relying on anything here

This project is under active restructuring. Be precise about what's real:

Component	Status
On-prem endpoint collector (OS, patches, Defender, firewall)	✅ Real — PowerShell-backed, live data
Entra ID identity collector (users, groups, guests, stale accounts)	✅ Real — Microsoft Graph
Intune device collector (compliance, encryption, management state)	✅ Real — Microsoft Graph
Per-tenant orchestrator (runs the right plane per client)	✅ Real
National-cloud support (commercial / GCC / GCC High / DoD)	✅ Real for app-registration auth; GDAP and interactive auth are unimplemented seams
On-prem AD, event log, and policy collectors	✅ Real — LDAP (AD) and PowerShell-backed (event log, policy)
Compliance scoring	⚠️ Placeholder heuristics — not yet mapped to real 800-171 practices or SPRS methodology
SSP / POA&M generation	❌ Not started

Do not use this to make a real compliance claim yet. The collection layer is being built out module by module; scoring in particular needs a full rework before its output means anything to an assessor. See CMMC-TOOL-BUILD-PLAN.md for the phased roadmap.

Architecture

Two collection planes feed the same artifact models, scorer, and exporters — each tenant runs whichever plane(s) apply to their environment.

src/cmmc_gatherer/
├── collectors/
│   ├── base.py                    # shared CollectorBase interface
│   ├── onprem/                    # Windows / on-prem AD plane
│   │   ├── endpoint_collector.py  # + collect_endpoint.ps1
│   │   ├── ad_collector.py
│   │   ├── event_log_collector.py
│   │   └── policy_collector.py
│   └── cloud/                     # Entra ID / Intune plane
│       ├── entra_identity_collector.py
│       └── intune_device_collector.py
├── cloud/
│   ├── cloud_config.py            # national-cloud registry + TenantProfile
│   └── graph.py                   # Graph auth providers + paged client
├── models/artifacts.py            # shared artifact types (Endpoint, ADObject, ...)
├── utils/                         # scoring, PII filtering, multi-tenant management
├── exporters/                     # JSON / CSV / XML / HTML / MSP report
├── orchestrator.py                # per-tenant: picks plane(s), runs collectors
└── gatherer.py                    # top-level entry point

Why two planes, one model set: an on-prem endpoint and an Intune-managed device don't expose the same fields — a centrally managed device has no local firewall-profile concept, for instance. Rather than force a fit, cloud collectors map what genuinely translates and put the rest in metadata, so nothing is silently fabricated to make the schema line up.

Multi-cloud by design: cloud/cloud_config.py holds a small registry mapping each national cloud (commercial, GCC, GCC High, DoD) to its correct Microsoft Graph endpoint and login authority. A TenantProfile declares which cloud a client is in; the Graph client and auth provider read that and target the right endpoint automatically — commercial and GCC High are both just configuration, not separate code paths.

Getting started
bash
pip install -r requirements.txt

Requires Python 3.8+. On-prem collection requires PowerShell 5.1+ on the target Windows host. Cloud collection requires an Entra app registration in the tenant's own national cloud (a commercial app registration cannot authenticate a GCC High tenant) with admin-consented Graph permissions: User.Read.All, Group.Read.All, AuditLog.Read.All, DeviceManagementManagedDevices.Read.All.

Run the on-prem endpoint collector locally:

python
from cmmc_gatherer.collectors.onprem.endpoint_collector import EndpointCollector

# demo=True returns canned data with no Windows host required — useful for
# exercising the pipeline before pointing it at a real machine.
endpoints = EndpointCollector(demo=True).collect()

Run a full per-tenant collection (on-prem + cloud, mixed):

python
from cmmc_gatherer.cloud.cloud_config import TenantProfile, NationalCloud, Plane, AuthMethod
from cmmc_gatherer.orchestrator import TenantOrchestrator

def get_secret(secret_ref: str) -> str:
    # Look this up in your own vault/secret store — never hardcode it here.
    ...

profile = TenantProfile(
    tenant_key="acme",
    display_name="Acme Corp",
    national_cloud=NationalCloud.GCC_HIGH,
    planes=[Plane.CLOUD],
    auth_method=AuthMethod.APP_REGISTRATION,
    tenant_id="<entra-tenant-guid>",
    client_id="<app-registration-client-id>",
    secret_ref="acme-graph-client-secret",
)

orchestrator = TenantOrchestrator(secret_resolver=get_secret)
result = orchestrator.run_one(profile)
print(result.collection, result.errors)
Regulatory accuracy — a standing caution

CMMC levels, the 800-171 revision in force, and SPRS scoring weights change over time and are not hardcoded in this codebase for that reason — treat any control list or weight as external, versioned configuration once the scoring rework lands, and verify current requirements against official DoD/CMMC sources before relying on a score for an actual assessment.

Collected evidence (AD/Entra inventory, event history, policy state) should itself be treated as sensitive (CUI/FCI-adjacent) in storage and transport, not as casual JSON on disk.

Roadmap

See CMMC-TOOL-BUILD-PLAN.md for the full phased plan — remaining on-prem collectors, real 800-171 scoring, SSP/POA&M generation, and multi-tenant hardening.

Credit

Forked from tkhemraj/cmmc by Tarique Khemraj, which provided the original collector/model/exporter architecture. This fork rebuilds the collection and scoring engine and adds a cloud (Entra ID / Intune) collection plane alongside the original Windows/AD focus.

License

MIT — see LICENSE.
