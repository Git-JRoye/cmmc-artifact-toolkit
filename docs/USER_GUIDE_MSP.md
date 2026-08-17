# CMMC Artifact Toolkit — User Guide for MSPs (Multiple Clients)

**This is a living document.** It gets updated every time a feature is
added. If something in here doesn't match what the tool actually does,
the tool's behavior is correct and this doc needs an update — flag it.

This guide is for an MSP running CMMC assessments across **multiple
client tenants**. If you're assessing just your own organization, see
`USER_GUIDE_SINGLE_ORG.md` instead — everything in that guide's "What this
tool does" and "Reading the report" sections applies here too; this guide
focuses on what's different at multi-client scale.

---

## 1. The core idea: one config file, one entry per client

Every client lives as one entry in `tenants.yaml`. Nothing about adding a
new client touches source code — it's editing a config file. The config
has three top-level sections: `app:` for your shared app registration,
`defaults:` for settings inherited by every client, and `clients:` for
each client's entry.

```yaml
app:
  client_id: "your-multi-tenant-app-client-id"
  secret_ref: "MSP_SHARED_APP_SECRET"

defaults:
  national_cloud: commercial
  planes: [cloud]
  auth_method: app_registration

clients:
  - tenant_key: acme
    display_name: "Acme Corporation"
    tenant_id: "..."
  - tenant_key: globex
    display_name: "Globex Corporation"
    tenant_id: "..."
```

Run one client, or all of them, with the same command:

```powershell
python run_assessment.py                          # every client in tenants.yaml
python run_assessment.py --tenant acme            # one client
python run_assessment.py --config tenants.yaml    # use a different config file
python run_assessment.py --list                   # see what's configured, with validation
```

`--list` validates every profile before running anything — a
misconfigured client shows up immediately as `[INVALID CONFIG: ...]`
rather than failing partway through a real run.

---

## 2. Connecting to client cloud tenants

### Recommended: one shared, multi-tenant app registration

This is the default approach and what you should use for the vast majority
of clients. Register **one** app registration in your own tenant, set
"Supported account types" to *"Accounts in any organizational directory"*
(multi-tenant), and grant it the same permission list as the single-org
guide. Then define it once in the `app:` section of your config:

```yaml
app:
  client_id: "55555555-5555-5555-5555-555555555555"
  secret_ref: "MSP_SHARED_APP_SECRET"
```

Each client just needs to visit an admin-consent URL to approve your
requested permissions for their own tenant — **no app registration on
their end at all**:

```
https://login.microsoftonline.com/{their-tenant-id}/adminconsent?client_id={your-app-id}
```

Once they approve, add three lines to your config. Each client inherits
`client_id` and `secret_ref` from the `app:` section by default — only
`tenant_id` differs:

```yaml
clients:
  - tenant_key: wayne_enterprises
    display_name: "Wayne Enterprises"
    tenant_id: "44444444-4444-4444-4444-444444444444"

  - tenant_key: stark_industries
    display_name: "Stark Industries"
    tenant_id: "66666666-6666-6666-6666-666666666666"
```

### Adding a new client (5 minutes)

1. Get the client's Entra tenant ID (Azure Portal -> Entra ID -> Overview)
2. Send the client admin the consent URL:
   `https://login.microsoftonline.com/{their-tenant-id}/adminconsent?client_id={your-app-id}`
3. After they approve, add 3 lines to tenants.yaml:
   ```yaml
   - tenant_key: clientname
     display_name: "Client Name"
     tenant_id: "their-tenant-guid"
   ```
4. Run: `python run_assessment.py --tenant clientname`

### Option B — a dedicated app registration per client

For GCC High or DoD tenants, or other special cases where the shared app
cannot reach the client's cloud, each client creates their own app
registration (or you create one in their tenant). In this case, override
`client_id` and `secret_ref` directly on the client entry:

```yaml
clients:
  - tenant_key: dod_contractor
    display_name: "DoD Contractor Inc."
    national_cloud: gcchigh
    tenant_id: "77777777-7777-7777-7777-777777777777"
    client_id: "88888888-8888-8888-8888-888888888888"
    secret_ref: "DOD_CONTRACTOR_APP_SECRET"
```

**Hard limit:** the multi-tenant shared app only works *within one
national cloud*. A multi-tenant app registered in the commercial cloud
(GCC rides commercial, so this covers GCC too) can never reach a GCC High
or DoD tenant — those are a completely separate Entra namespace. A GCC
High/DoD client always needs Option B: their own app registration, created
inside that specific cloud.

See `tenants.example.yaml`'s Example 4 for the full worked config.

**GDAP is not implemented.** This shared-app pattern gets you most of the
practical benefit (no per-client app registration to create), but it's
not the same as Microsoft's formal delegated-admin model for MSPs. If you
need that specifically, it remains a documented, unbuilt seam.

---

## 3. On-prem collection at MSP scale — the real limitation

**Be honest with yourself about this one.** On-prem collection (endpoint
posture, event logs, local security policy) currently only runs **locally**
on whatever single machine executes the script. There is no
fleet-wide/remote-execution capability today — `collect_remote()` exists
in the code as a documented stub (WinRM-based) but has no real credential
handling wired up, and nothing in the orchestrator calls it.

**This is not the same problem as "how do I reach every one of a client's
200 devices."** Per the actual CMMC Assessment Process (CAP v2.0), real
C3PAO assessors don't examine every device either — they use a
**nonstatistical, representative sample**, sized by "FOCUSED" depth and
coverage for Level 2, expanding the sample only if something looks
questionable. So the realistic path forward isn't building infrastructure
to reach every endpoint — it's:

1. Deciding, per client, **which devices are actually in CMMC Assessment
   Scope at all** (see §4 — a lot of a 200-device fleet may be
   Out-of-Scope or CRMA before you even get to sampling).
2. Reaching a **representative sample** of what's left — a much smaller,
   more tractable number than the whole fleet.
3. Actually reaching that sample: either finish the WinRM remote-execution
   path, or (more practically, if you already run an RMM like Action1,
   NinjaOne, ConnectWise, etc. across client fleets) have the RMM push and
   schedule the same collection script, with results centralized somewhere
   this tool can read.

None of that is built yet. Track it as the next major piece of work, not
something to route around by trying to reach every device by hand.

**Cloud collection has no equivalent problem** — Microsoft Graph
auto-discovers every user, group, and Intune-enrolled device the moment
the app registration has access. There's no host list to maintain for the
cloud plane.

---

## 4. Asset scope, per client

Each client gets their own, independent `asset_scope` block, living
inside their own tenant entry — same place as their connection details.
This is a per-client compliance decision, completely separate from *how*
you're connected to them (shared app or dedicated app from §2).

```yaml
clients:
  - tenant_key: wayne_enterprises
    ...
    asset_scope:
      default: cui_asset
      exceptions:
        - identifier_type: hostname
          identifier: WAYNE-GUEST-WIFI
          category: out_of_scope
          reason: "Guest network, physically separate"

  - tenant_key: stark_industries
    ...
    asset_scope:
      default: cui_asset
      exceptions:
        - identifier_type: hostname
          identifier: STARK-R&D-LAB-PLC
          category: specialized
          reason: "Operational Technology — R&D lab equipment"
```

For a client with a longer exceptions list, point at a CSV instead of
typing everything into YAML — see `USER_GUIDE_SINGLE_ORG.md` §6 for the
exact CSV format (identical for MSP use, just one file per client).

**GCC High / FedRAMP clients typically need no `asset_scope` block at
all.** Organizations move to GCC High specifically because most or all of
their environment is CUI-relevant — the built-in default (everything is a
CUI Asset, fully assessed) already means "scan and score everything,"
correctly, with zero configuration. The same mechanism serves a
heavily-mixed commercial client (several exceptions) and a GCC High
client (none) without the tool needing to know or care which situation
it's in.

**Categorization is never inferred or guessed at.** For every client,
this is a real decision — usually already documented in their SSP, or
made as part of a scoping conversation with them — never something an
automated heuristic decides on your behalf.

---

## 5. A note on report file naming at scale

Every client produces its own, separately named set of three files:

```
report_acme.html          report_acme_software.html          report_acme_health.html
report_globex.html        report_globex_software.html        report_globex_health.html
report_initech.html       report_initech_software.html       report_initech_health.html
```

Running all clients across N clients produces 3N files, all clearly
distinguishable by the `tenant_key` in the filename, and each report's own
header/title also states the client's `display_name` — so there's never
ambiguity about which report belongs to which client, even with a large
client book. The `_health.html` file is worth checking across your whole
book after a batch run — it's the fastest way to spot which clients (if
any) hit a real collection error versus a clean run, without opening
every main report.

---

## 6. Known limitations (as of this writing)

Everything in `USER_GUIDE_SINGLE_ORG.md` §7 applies here too — including
Intune administrative role assignments showing a count rather than
individual member names, device sanitization/remote-wipe evidence being
genuinely unverified against a live tenant, and no Exchange Online mailbox
evidence. MDE (Microsoft Defender for Endpoint) collectors are now
integrated. Additionally, at MSP scale specifically:

- **On-prem fleet collection is unbuilt** — see §3. This is the single
  biggest open item for real MSP scale.
- **GDAP is unimplemented** — the shared multi-tenant app pattern (§2)
  covers most of the practical need today, but isn't Microsoft's
  formal MSP delegated-access model.
- **Device merge logic** (combining an on-prem scan and an Intune record
  of the same physical machine into one report entry) is implemented and
  unit-tested, but has not yet been proven against a real, single-profile
  hybrid client in production — only against separate on-prem/cloud
  profiles in the pilot so far.
- **Device Ownership (Corporate vs. Personal/BYOD)** is read via its own
  isolated per-device Graph call — if it fails for a given device
  (permission gap, tenant quirk), that one device shows "Unknown"
  ownership and everything else about it is unaffected; check that
  client's `_health.html` if you see this happening across a whole book.

---

*Last updated: covers everything through Collection Health, enterprise
app inventory with resolved permission names, security alerts, real-time
Defender health, real per-device cloud firewall status, BitLocker escrow,
device ownership type, granular auth method type, Intune App Protection
Policy, Intune RBAC role assignments, MDE integration, and device
sanitization events. Add to this section as new features land — don't let
this drift from what the tool actually does.*
