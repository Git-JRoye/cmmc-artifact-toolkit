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
On-prem endpoint collector (OS, patches, Defender, firewall, installed software)	✅ Real — PowerShell-backed, live data
Entra ID identity collector (users, groups, guests, stale accounts, MFA, privileged roles, group membership, granular per-user auth method type)	✅ Real — Microsoft Graph; auth method detail recalled against documentation, not independently verified
Enterprise application / service principal inventory	✅ Real — Microsoft Graph; permission grants resolved to real names (e.g. `Directory.ReadWrite.All`), not just a count, with a high-privilege permission watchlist flagged separately — confirmed against a real tenant
Intune device collector (compliance, encryption, management state, installed software, real-time Defender health, real per-device firewall status, BitLocker recovery key escrow, device ownership)	✅ Real — Microsoft Graph
Cloud security events (Entra sign-in/directory audit logs, unified Graph Security API alerts)	✅ Real — Microsoft Graph
Cloud policy collector (Conditional Access, Intune configuration profiles, Intune compliance policies, Windows Update Ring, Intune App Protection Policies for BYOD/MAM)	✅ Real — Microsoft Graph; on-prem and cloud evidence for the same setting (e.g. minimum password length) are scored by one identical rule
Intune administrative role assignments (distinct from Entra directory roles)	✅ Real — Microsoft Graph; assigned-principal count per role, individual member names not yet resolved
Per-tenant orchestrator (runs the right plane per client)	✅ Real
National-cloud support (commercial / GCC / GCC High / DoD)	✅ Real for app-registration auth; GDAP and interactive auth are unimplemented seams
On-prem AD, event log, and policy collectors (incl. time synchronization)	✅ Real — LDAP (AD) and PowerShell-backed (event log, policy); AD collector not yet run against a real domain controller
Compliance scoring	✅ Real — six-dimension weighted scorer, with the full weight/score/coverage breakdown shown in the report, not just a final number
CMMC/NIST 800-171 practice mapping	✅ Real — evidence is mapped to specific practice IDs (e.g. IA.L2-3.5.3, AU.L2-3.3.7, SC.L2-3.13.10), tagged DIRECT or SUPPORTING confidence, shown in a domain-grouped navigation section
CMMC asset scope (CUI Asset / SPA / CRMA / Specialized / Out-of-Scope)	✅ Real — per-tenant config, defaults to "everything in scope," excludes/documents assets per the CMMC Assessment Guide's categorization
Collection Health reporting	✅ Real — every collector warning/error is captured and shown in the report itself (always-present page + summary), not only the console
SSP / POA&M generation	❌ Not started
Exchange Online mailbox evidence (audit logging, forwarding, DKIM/DMARC)	❌ Not started — needs a separate connection mechanism from Graph
Remote/fleet-wide on-prem collection	❌ Not started — currently only runs locally on the machine executing the script
Remote wipe / device sanitization evidence (Media Protection domain)	✅ Real — Microsoft Graph (`deviceManagement/auditEvents`), mapped to `MP.L1-3.8.3`; genuinely unverified against a live tenant — the least-confident endpoint in the codebase, confirm the permission and event shape before relying on it

Do not use this to make a real compliance claim without a qualified reviewer. See `docs/GETTING_STARTED.md` for installation, and `CMMC-TOOL-BUILD-PLAN.md` for the phased roadmap.

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
│       ├── service_principal_collector.py   # enterprise app / service principal inventory + permission names
│       ├── intune_device_collector.py       # + BitLocker escrow, real-time Defender health, firewall status, ownership
│       ├── intune_rbac_collector.py         # Intune administrative role assignments
│       ├── cloud_event_collector.py         # sign-in/audit logs + Graph Security API alerts + device sanitization events
│       └── cloud_policy_collector.py        # Conditional Access, Intune config/compliance policies, Update Ring, App Protection Policy
├── cloud/
│   ├── cloud_config.py            # national-cloud registry + TenantProfile
│   └── graph.py                   # Graph auth providers + paged client
├── models/artifacts.py            # shared artifact types (Endpoint, ADObject, ...)
├── asset_scope.py                 # CMMC asset categorization (CUI Asset/SPA/CRMA/Specialized/Out-of-Scope)
├── collection_health.py           # captures collector warnings/errors into the report itself
├── control_mapping.py             # evidence -> CMMC practice registry (DIRECT/SUPPORTING confidence)
├── utils/                         # scoring, PII filtering, multi-tenant management
├── exporters/                     # JSON / CSV / XML / HTML / MSP report
├── orchestrator.py                # per-tenant: picks plane(s), runs collectors
└── gatherer.py                    # top-level entry point

Why two planes, one model set: an on-prem endpoint and an Intune-managed device don't expose the same fields — a centrally managed device has no local firewall-profile concept, for instance. Rather than force a fit, cloud collectors map what genuinely translates and put the rest in metadata, so nothing is silently fabricated to make the schema line up.

Multi-cloud by design: cloud/cloud_config.py holds a small registry mapping each national cloud (commercial, GCC, GCC High, DoD) to its correct Microsoft Graph endpoint and login authority. A TenantProfile declares which cloud a client is in; the Graph client and auth provider read that and target the right endpoint automatically — commercial and GCC High are both just configuration, not separate code paths.

Getting started

See `docs/GETTING_STARTED.md` for full installation instructions (Python
setup, downloading the repo, installing dependencies) if this is your
first time here.

Once installed, configuration and running a real assessment is documented in:
- `docs/USER_GUIDE_SINGLE_ORG.md` — assessing one organization
- `docs/USER_GUIDE_MSP.md` — assessing multiple client tenants

Quick reference once set up:
```bash
pip install -r requirements.txt
cp tenants.example.yaml tenants.yaml   # fill in your real environment's details
python run_assessment.py --config tenants.yaml --list   # validate config, no real collection yet
python run_assessment.py --all                          # run every configured tenant
```

Requires Python 3.10+. On-prem collection requires PowerShell 5.1+ on the target Windows host. Cloud collection requires an Entra app registration in the tenant's own national cloud (a commercial app registration cannot authenticate a GCC High tenant) with admin-consented Graph permissions — the full current list is in `docs/USER_GUIDE_SINGLE_ORG.md` §3.3.
Regulatory accuracy — a standing caution

CMMC levels, the 800-171 revision in force, and SPRS scoring weights change over time and are not hardcoded in this codebase for that reason — treat any control list or weight as external, versioned configuration once the scoring rework lands, and verify current requirements against official DoD/CMMC sources before relying on a score for an actual assessment.

Collected evidence (AD/Entra inventory, event history, policy state) should itself be treated as sensitive (CUI/FCI-adjacent) in storage and transport, not as casual JSON on disk.

Roadmap

See CMMC-TOOL-BUILD-PLAN.md for the full phased plan — remaining on-prem collectors, real 800-171 scoring, SSP/POA&M generation, and multi-tenant hardening.

Credit

Forked from tkhemraj/cmmc by Tarique Khemraj, which provided the original collector/model/exporter architecture. This fork rebuilds the collection and scoring engine and adds a cloud (Entra ID / Intune) collection plane alongside the original Windows/AD focus.

License

MIT — see LICENSE.
