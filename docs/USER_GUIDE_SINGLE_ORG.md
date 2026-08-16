# CMMC Artifact Toolkit — User Guide for a Single Organization

**This is a living document.** It gets updated every time a feature is
added. If something in here doesn't match what the tool actually does,
the tool's behavior is correct and this doc needs an update — flag it.

This guide is for a business running its **own** CMMC self-assessment
(one organization, not an MSP managing multiple clients — see
`USER_GUIDE_MSP.md` for that case).

---

## 1. What this tool does

Point it at your Windows environment (on-prem machines, your Entra ID /
Intune tenant, or both), and it:

1. Collects real evidence — endpoint security posture, Active Directory /
   Entra identity data, security policies, security events, installed
   software, Conditional Access and Intune configuration.
2. Scores that evidence against a weighted compliance model across six
   dimensions (firewall, antivirus, patch level, policy compliance, audit
   logging, AD/identity security).
3. Maps the evidence directly to specific CMMC/NIST 800-171 practices.
4. Produces a professional HTML report you can hand to an assessor, a
   client, or keep for your own records — plus a separate, linked page for
   the full installed-software inventory (kept out of the main report
   since it can get long).

It does **not** replace your SSP, your POA&M, or a real CMMC assessment.
It's evidence-gathering and scoring automation — the manual process of
logging into machines, running PowerShell, and copying results into a Word
doc, replaced with one command.

---

## 2. Prerequisites

- **Python 3.10+** with the packages in `requirements.txt` installed
  (`pip install -r requirements.txt`).
- **PowerShell** available locally, for on-prem collection (Windows-only —
  this collects Windows endpoint data specifically).
- **An elevated terminal** for on-prem collection — some checks (audit
  policy, GPO application) return incomplete data or errors without it.
- If you're assessing your Entra ID / Intune environment too: an **app
  registration** in your own tenant (see §4 below for the exact
  permissions needed).

---

## 3. One-time setup

### 3.1 Copy the example config

```powershell
cp tenants.example.yaml tenants.yaml
```

`tenants.yaml` is gitignored — it's where your real environment's details
live, and it should never be committed to source control.

### 3.2 Fill in your one tenant entry

For a single org, you'll have exactly one entry in `tenants.yaml`. Three
shapes, depending on what you're assessing:

**On-prem only** (Active Directory / local machines, no cloud):

```yaml
tenants:
  - tenant_key: mycompany
    display_name: "My Company Inc."
    planes:
      - onprem
    onprem:
      domain_controller: "dc01.mycompany.local"
      base_dn: "DC=mycompany,DC=local"
      bind_dn: "svc-cmmc@mycompany.local"
      secret_ref: "MYCOMPANY_LDAP_BIND_SECRET"
```

**Cloud only** (Entra ID / Intune, no on-prem AD):

```yaml
tenants:
  - tenant_key: mycompany
    display_name: "My Company Inc."
    national_cloud: commercial   # or gcc, gcc_high, dod
    planes:
      - cloud
    cloud:
      tenant_id: "your-entra-tenant-guid"
      client_id: "your-app-registration-client-id"
      secret_ref: "MYCOMPANY_GRAPH_CLIENT_SECRET"
```

**Hybrid** (both — the correct setup if you have both an on-prem domain
and Entra/Intune): combine both blocks under one `tenant_key`, with
`planes: [onprem, cloud]`. See `tenants.example.yaml`'s "Example 3" for
the full worked version. This also enables automatic device
de-duplication — if the same physical machine shows up in both your
on-prem scan and Intune, it's merged into one entry instead of counted
twice.

### 3.3 Set up the app registration (cloud only)

If you're assessing Entra/Intune, create an app registration in your
tenant (Entra admin center → App registrations → New registration),
single-tenant is fine for a single org. Grant these **application**
permissions, then **Grant admin consent**:

| Permission | Why |
|---|---|
| `User.Read.All` | Entra user inventory |
| `Group.Read.All` | Entra group inventory |
| `AuditLog.Read.All` | MFA registration status, sign-in/audit logs, stale-account detection |
| `DeviceManagementManagedDevices.Read.All` | Intune device inventory, installed software, real-time Defender health |
| `RoleManagement.Read.Directory` | Privileged role membership |
| `Reports.Read.All` | MFA registration report |
| `Policy.Read.All` | Conditional Access policies |
| `DeviceManagementConfiguration.Read.All` | Intune configuration profiles, compliance policies, Windows Update Ring settings |
| `BitlockerKey.ReadBasic.All` | BitLocker recovery key escrow status (existence check only — this tool never reads the key value itself; deliberately not `BitlockerKey.Read.All`) |
| `Application.Read.All` | Enterprise application / service principal inventory |
| `SecurityAlert.Read.All` | Security alerts from the unified Microsoft Graph Security API (Defender, Sentinel if connected) |

Generate a client secret (Certificates & secrets → New client secret) and
set it as an environment variable matching whatever `secret_ref` you put
in `tenants.yaml`:

```powershell
$env:MYCOMPANY_GRAPH_CLIENT_SECRET = "the real secret value"
```

**This is a real secret in plaintext in your terminal's environment.**
Fine for a single operator running this locally; if you ever automate
this or hand it to someone else, replace the environment-variable
resolver with a real secret vault (see `run_assessment.py`'s
`build_secret_resolver()` — that's the one place to swap it).

---

## 4. Running it

```powershell
python run_assessment.py --tenant mycompany
```

Or, since you only have one tenant anyway:

```powershell
python run_assessment.py --all
```

Output: `report_mycompany.html` (the main report), `report_mycompany_software.html`
(the full installed-software list), and `report_mycompany_health.html` (every
warning/error any collector logged during the run — always written, even when
completely clean) — all linked from the main report.

Check the console output for any errors — collection failures for one
plane don't stop the other from running, but you'll want to know about
them. The health page is the same information, permanently saved with the report.

---

## 5. Reading the report

- **Executive Summary** — customer, assessment ID/date, collection mode
  (on-prem/cloud/hybrid — reflects what was actually collected, not just
  configured), overall score, and scoring coverage.
- **Collection Health** (always shown, right after Executive Summary) —
  a warning/error count from this run with a link to the full
  `_health.html` page, or a plain "No collection issues this run" if
  clean. This is the same information previously visible only in the
  PowerShell console, now permanently saved with the report. A warning
  here means some evidence may be incomplete — it does not by itself mean
  your environment has a security problem.
- **Compliance Score** — the headline number. If coverage is incomplete
  (e.g. a cloud-only tenant has no firewall/antivirus data — that's not
  collectible from Intune the same way it is on-prem), a red banner says
  so explicitly, right under the score.
- **CMMC Assessment Scope** (only appears if you've configured
  `asset_scope` — see §6) — which devices/users were fully assessed vs.
  documented-but-excluded vs. excluded entirely, and why.
- **Scoring Breakdown** — the actual math: every category's weight,
  individual score, and share of the final number. Never take the
  headline percentage on faith — this shows exactly how it was derived.
- **Practices Evidenced in This Assessment** — a jump-nav grouped by CMMC
  domain (AC, AU, CM, IA, SC, SI), showing which specific practices this
  report provides real evidence for, each linked to the section that
  proves it. Every badge is tagged DIRECT (textbook match) or SUPPORTING
  (real but partial evidence) — never overstated.
- **On-Prem Endpoint Status / Cloud-Managed Devices (Intune)** — device
  tables. The cloud table now includes: BitLocker recovery key escrow
  status (existence check only — never the key itself), real-time
  Windows Defender health (distinct from, and more current than, the
  compliance-policy *requirement* check below), and device Ownership
  (Corporate vs. Personal/BYOD) — which is also the real, structural
  reason a device's software inventory may show "None detected": Intune
  deliberately restricts app-inventory collection on personally-owned
  devices for user privacy.
- **Active Directory / Identity Objects — Users / Groups** — on-prem AD
  and Entra users/groups, including per-user group membership.
- **Enterprise Applications** — every application/service principal
  registered in the tenant (processes acting on their own identity, not
  human users), with a permission-grant *count* per app. Specific
  permission names aren't resolved yet (see §7).
- **Findings & Recommendations** — every finding cites the specific CMMC
  practice it relates to where applicable.
- **Policy Compliance** — on-prem Local Security Policy/UAC/audit policy,
  Entra Conditional Access, and Intune configuration profiles,
  compliance policies (password/encryption/firewall/Defender
  *requirements*), and Windows Update Ring (patch deferral, automatic
  install). On-prem and cloud evidence for the *same* real-world setting
  (e.g. minimum password length) appear together in this one table,
  scored by the identical rule regardless of source.
- **Installed Software Inventory** — summarized here with a link to the
  full, separate page (`report_mycompany_software.html`), including a
  disclosure of exactly which devices aren't contributing and why
  (collection failed / confirmed empty — including the BYOD-specific
  reason / not attempted).
- **Security Events** — on-prem Windows event log data (if collected)
  plus Entra sign-in logs, directory audit logs, and security alerts from
  the unified Microsoft Graph Security API (surfacing whatever security
  product is actually deployed — Defender, Sentinel if connected).

---

## 6. Asset scope (optional, but important if your environment has a mix)

CMMC defines 5 asset categories: **CUI Assets** and **Security Protection
Assets** are fully assessed; **Contractor Risk Managed Assets** and
**Specialized Assets** are documented but not scored; **Out-of-Scope
Assets** are excluded from the assessment entirely (per the CMMC
Assessment Guide: out-of-scope assets "should not be part of the CMMC
assessment engagement").

**If your whole environment is in scope** (common for a GCC High tenant,
for example), you don't need to do anything here — everything defaults to
CUI Asset and gets fully assessed.

**If some devices/users aren't fully in scope** (a guest wifi device, an
HR-only workstation, IoT/OT equipment), list only those exceptions —
everything else still defaults automatically:

```yaml
    asset_scope:
      default: cui_asset
      exceptions:
        - identifier_type: hostname
          identifier: PRINTER-01
          category: out_of_scope
          reason: "Network printer, no CUI processing capability"
        - identifier_type: user
          identifier: contractor@mycompany.com
          category: crma
          reason: "Limited-access contractor account per SSP"
```

For a longer list, use a CSV file instead of typing each one into YAML —
build/edit it in Excel:

```yaml
    asset_scope:
      default: cui_asset
      exceptions_file: mycompany_asset_exceptions.csv
```

CSV format (header row required):

```csv
identifier_type,identifier,category,reason
hostname,PRINTER-01,out_of_scope,"Network printer, no CUI processing capability"
user,contractor@mycompany.com,crma,"Limited-access contractor account per SSP"
```

- `identifier_type`: `hostname` or `user`
- `identifier`: matches a collected device's hostname, or a user's
  UPN/distinguished name
- `category`: one of `cui_asset`, `spa`, `crma`, `specialized`,
  `out_of_scope`
- `reason`: **required** — this is exactly the justification your SSP
  needs for this asset's categorization anyway; it's reused directly in
  the generated report.

You can combine inline `exceptions:` and `exceptions_file:` — both get
applied together. Anything you list that never actually matches a real
collected device/user gets flagged in the report as possible config
drift (a typo, a renamed device, a decommissioned machine).

**Categorization is never guessed at automatically.** The CMMC guide is
explicit that this is a human, policy-driven decision you must be able to
defend — this tool only ever applies exactly what you declare.

---

## 7. Known limitations (as of this writing)

- **On-prem collection only runs locally**, on whatever machine executes
  the script. There's no remote-execution/fleet-scan capability yet — for
  a single machine (your own), this is fine as-is.
- **Patch scoring only checks presence of hotfix history**, not recency
  against a current baseline.
- **On-prem AD collector has never been run against a real domain
  controller** — only in demo mode. If you're assessing on-prem AD, treat
  this as unverified until you've confirmed it works against your own DC.
- **Device merge logic** (combining an on-prem scan and an Intune record
  of the same physical machine into one report entry) is implemented and
  unit-tested, but not yet proven on a real hybrid client running as a
  single profile — see `USER_GUIDE_MSP.md` for the hybrid config that
  would actually exercise it.
- **Enterprise Applications shows a permission-grant *count* per app, not
  the specific permission names** — resolving those requires an
  additional lookup this tool doesn't do yet.
- **Vulnerability scanning is not integrated**, and there's no per-device
  firewall/antivirus *state* for cloud-only devices (only the compliance-
  policy *requirement* and real-time Defender health) — a fuller
  Defender for Endpoint integration is a real, deferred next step.
- **Remote wipe / device sanitization evidence (Media Protection domain)
  is not collected** — real CMMC relevance (`MP.L1-3.8.3`), not yet built.
- **Exchange Online mailbox security settings** (audit logging, external
  forwarding rules, DKIM/DMARC) are not collected — this needs a separate
  connection mechanism from the Graph client everything else uses, and is
  a deliberately separate future project, not a quick add.
- **GDAP is not implemented** — every cloud tenant needs its own app
  registration (or the shared multi-tenant-app pattern in
  `USER_GUIDE_MSP.md`), not Microsoft's formal MSP delegated-access model.

---

*Last updated: covers everything through Collection Health, enterprise
app inventory, security alerts, real-time Defender health, BitLocker
escrow, and device ownership type. Add to this section as new features
land — don't let this drift from what the tool actually does.*
