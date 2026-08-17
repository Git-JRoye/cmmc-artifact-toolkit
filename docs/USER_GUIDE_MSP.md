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
new client touches source code — it's editing a config file. Each entry
is independent: different tenant IDs, different auth, different asset
scope, different collection planes, all coexisting in the same file.

```yaml
tenants:
  - tenant_key: acme
    display_name: "Acme Corporation"
    ...
  - tenant_key: globex
    display_name: "Globex Corporation"
    ...
  - tenant_key: initech
    display_name: "Initech LLC"
    ...
```

Run one client, or all of them, with the same command:

```powershell
python run_assessment.py --tenant acme        # one client
python run_assessment.py --all                # every client in tenants.yaml
python run_assessment.py --config tenants.yaml --list   # see what's configured, with validation
```

`--list` validates every profile before running anything — a
misconfigured client shows up immediately as `[INVALID CONFIG: ...]`
rather than failing partway through a real run.

---

## 2. Two ways to connect to a client's cloud tenant

### Option A — a dedicated app registration per client

Each client creates their own app registration (or you create one in
their tenant), grants the same permission list as the single-org guide,
and hands you the tenant ID / client ID / secret. Simple to reason about,
but a real setup step per client.

### Option B — one shared, multi-tenant app registration (recommended past a handful of clients)

Set **one** app registration's "Supported account types" to *"Accounts in
any organizational directory"* (multi-tenant). A new client then just
visits an admin-consent URL and approves your requested permissions for
their own tenant — **no app registration on their end at all**:

```
https://login.microsoftonline.com/{their-tenant-id}/adminconsent?client_id={your-app-id}
```

Every client using this shared app reuses the **same** `client_id` and
`secret_ref` — only `tenant_id` differs per client:

```yaml
tenants:
  - tenant_key: wayne_enterprises
    display_name: "Wayne Enterprises"
    national_cloud: commercial
    planes: [cloud]
    cloud:
      tenant_id: "44444444-4444-4444-4444-444444444444"   # differs per client
      client_id: "55555555-5555-5555-5555-555555555555"   # SAME shared app
      secret_ref: "MSP_SHARED_APP_SECRET"                  # SAME shared app

  - tenant_key: stark_industries
    display_name: "Stark Industries"
    national_cloud: commercial
    planes: [cloud]
    cloud:
      tenant_id: "66666666-6666-6666-6666-666666666666"   # different tenant
      client_id: "55555555-5555-5555-5555-555555555555"   # reused
      secret_ref: "MSP_SHARED_APP_SECRET"                  # reused
```

**Hard limit:** this only works *within one national cloud*. A
multi-tenant app registered in the commercial cloud (GCC rides commercial,
so this covers GCC too) can never reach a GCC High or DoD tenant — those
are a completely separate Entra namespace. A GCC High/DoD client always
needs Option A: their own app registration, created inside that specific
cloud.

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
you're connected to them (Option A or B from §2).

```yaml
tenants:
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

Running `--all` across N clients produces 3N files, all clearly
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
genuinely unverified against a live tenant, no Exchange Online mailbox
evidence, and no fuller Defender for Endpoint integration. Additionally,
at MSP scale specifically:

- **On-prem fleet collection is unbuilt** — see §3. This is the single
  biggest open item for real MSP scale.
- **GDAP is unimplemented** — the shared multi-tenant app pattern (§2,
  Option B) covers most of the practical need today, but isn't Microsoft's
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
Policy, Intune RBAC role assignments, and device sanitization events. Add
to this section as new features land — don't let this drift from what the
tool actually does.*
