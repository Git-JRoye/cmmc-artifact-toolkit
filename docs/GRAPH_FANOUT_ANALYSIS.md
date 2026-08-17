# Per-user / per-device Graph fan-out — analysis (no code changes)

This is an assessment, not a plan — written to support a decision, not to
be implemented as-is. It covers what actually calls Graph once per user or
per device today, which of those could become bulk/batch calls, which
genuinely can't, and what an "opt out of expensive enrichment" flag would
need to touch if we build one later.

## What's actually happening today (corrected counts)

Reading the collectors directly rather than estimating: the real fan-out
is **4 calls per device** and **2 calls per user**, not the "~5N / 3N"
figure floated when this review was requested — two device-side and
one user-side lookup already ARE bulk, tenant-wide calls, not per-object.

### Per-device (`intune_device_collector.py`), for each of N managed devices

| # | Call | Purpose | Bulk today? |
|---|------|---------|--------------|
| 1 | `deviceManagement/managedDevices/{id}/detectedApps` (`/beta`) | Installed software (CM.L2-3.4.1) | No |
| 2 | `informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{aadId}'` (`/beta`) | BitLocker key escrow existence (SC.L2-3.13.10) | No |
| 3 | `deviceManagement/managedDevices/{id}/windowsProtectionState` | Real-time Defender health (SI.L1-3.14.2) | No |
| 4 | `deviceManagement/managedDevices/{id}` with `$select=managedDeviceOwnerType` | Corporate vs. personal/BYOD | No |

Firewall status is **already bulk** — one `exportJobs` report call for the
whole tenant (`_collect_firewall_statuses`), joined back to devices by
hostname. That conversion already happened this project; it's the
template for what a fix to the other four would look like.

### Per-user (`entra_identity_collector.py`), for each of N users

| # | Call | Purpose | Bulk today? |
|---|------|---------|--------------|
| 1 | `users/{id}/memberOf` | Group membership display | No |
| 2 | `users/{id}/authentication/methods` | Granular auth method type/strength | No |

Privileged role membership and MFA registration status are **already
bulk-shaped** and need no change:
- Privileged roles: 1 call to list directory roles (`directoryRoles`) + 1
  call per **role** (not per user) to list its members. Roles number in
  the dozens at most even in a large tenant — this doesn't scale with N.
- MFA registration: `reports/authenticationMethods/userRegistrationDetails`
  returns every user's status in one paged call.

### Not a scaling concern at all

`cloud_policy_collector.py`'s per-profile `deviceStatusOverview` call
fans out once per **configuration profile** (M), not per device or user.
M is typically single digits to low tens even at a large client — this
doesn't need fixing for the scale this review is about.

### Realistic volume at "a few hundred devices"

At 300 devices + 300 users: roughly `1 + 4×300` device-side calls
(≈1,200) + `1 + 1(+M) + 2×300` user-side calls (≈600), each subject to
Graph's own throttling/retry — call it **~1,800 Graph requests per tenant
run**. That's the number a fix should actually be measured against, not
5N/3N.

## Per-lookup disposition

### Strong bulk-conversion candidates

**Installed software (detectedApps).** Intune's `exportJobs` reporting
API — the exact mechanism already built and pilot-confirmed for firewall
status (`GraphClient.run_export_job`) — has a real, documented report for
device-level detected-app inventory (commonly surfaced in the Intune
admin center as "Discovered apps" / raw app inventory export). This is
the same shape of fix already proven once in this codebase: one export
job for the whole tenant, joined back to devices client-side, instead of
N per-device calls. **Highest-confidence candidate** for a first fix,
specifically because the pattern is already implemented and tested
elsewhere in this file — this would be extending a working mechanism, not
inventing a new one.

**BitLocker key escrow.** The per-device call filters
`informationProtection/bitlocker/recoveryKeys` by `deviceId eq '...'`.
That collection almost certainly supports being listed **without** a
filter (paginated, like every other Graph collection in this codebase),
which would turn N filtered calls into one bulk list + a client-side
group-by-`deviceId`. This is a smaller, more contained change than the
firewall fix was (no async export-job flow needed, just dropping the
`$filter` and grouping), but genuinely unverified until tried against a
real tenant — the collection could be large enough that Graph paginates
it heavily, which is still strictly better than N separate round-trips
and N separate throttling risks.

### Must stay per-object (no known bulk shape) — but batchable

**Group membership (`memberOf`)** and **granular auth method detail
(`authentication/methods`)** don't have a tenant-wide report equivalent
the way firewall status or MFA registration do — Graph doesn't expose
"every user's group memberships" or "every user's registered auth
methods" as one exportable resource. These are genuinely per-user data.

That doesn't mean N round-trips is the only option, though: Microsoft
Graph's **JSON batching** (`POST /$batch`, up to 20 sub-requests per HTTP
call) is designed for exactly this shape — many small GETs against
different resource paths, collapsed into one HTTP request. `GraphClient`
doesn't implement `$batch` today (only `get_all`/`get_one`/`post_one`).
Adding it would cut N HTTP round-trips to roughly N/20 for **both** of
these lookups at once, without needing a bulk report for either — this is
probably the single highest-leverage fix available here, because it
applies uniformly rather than needing a bespoke report per feature.

### Ambiguous — needs a live-tenant experiment before committing either way

**Real-time Defender health (`windowsProtectionState`).** No confirmed
bulk report name for this today (unlike firewall, which was confirmed via
browser dev-tools network capture against a real tenant before this
project built `run_export_job` for it). Intune's admin center does have
Defender/antivirus agent status reporting, so a report equivalent
plausibly exists — but nothing in this codebase has looked for it yet,
and guessing a report name has already gone wrong once this project (the
original `getCachedReport` dead end). Recommend the same discovery process
used for firewall status — inspect real Intune admin-center network
traffic for the Defender/antivirus report — before assuming this is
convertible.

**Device ownership type (`managedDeviceOwnerType`).** This one has a
specific, documented scar: an *earlier, wrongly-named* attempt
(`ownerType`) to add this to the shared `managedDevices` `$select` caused
a 400 that broke the entire device list at once — the single worst
failure mode found in this project. The field name is now known to be
correct (`managedDeviceOwnerType`, confirmed working via the isolated
per-device call), which means folding it back into the bulk `$select` is
*plausible* — the original failure was a wrong field name, not evidence
that this property can't be bulk-selected at all. But given the blast
radius if that assumption is wrong twice, this is a "test in isolation
against a real tenant, on a branch, before touching the shared query"
change, not a confident recommendation either way. The existing isolated
per-device fallback should stay regardless of the outcome — it's the
safety net that made the original regression recoverable in the first
place.

## What an "opt out of expensive enrichment" flag would need to touch

1. **Config surface.** A per-tenant setting, not a global one — a 5-device
   single-org client has no reason to skip anything, while a 300-device
   MSP client might want to. Following the existing `asset_scope`
   precedent (opt-in, lives on `TenantProfile`/in `tenants.yaml`, absent =
   current full-enrichment behavior = no behavior change for anyone who
   doesn't touch it) is the natural shape. Per-feature flags (skip
   installed-software / BitLocker escrow / Defender health / ownership /
   group membership / auth method detail) fit this project's evidence
   model better than one all-or-nothing switch — `control_mapping.py`
   already treats each of these as a separate `EvidenceMapping` entry with
   its own CMMC relevance, and a client might reasonably want BitLocker
   escrow evidence but not care about group membership detail.

2. **Collector call sites.** Each lookup in `intune_device_collector.py`
   and `entra_identity_collector.py` is already isolated in its own
   try/except — gating each behind a flag check is additive to that
   existing structure, not a rework of it. The field(s) that lookup would
   have populated need to stay present (as `None`) rather than simply
   absent, matching every other three-state pattern already in this
   codebase (ok / confirmed-empty-or-false / failed) — a fourth state,
   "skipped by configuration," distinct from "attempted and failed."

3. **Collection Health semantics.** A skipped-by-choice lookup must never
   log a WARNING/ERROR — that channel is reserved for real problems, and
   `CollectionHealthRecorder` would otherwise make an intentional,
   configured skip look like a collection failure on the report's Health
   page. It needs its own signal, and the report's existing "why is this
   evidence missing" disclosures (the software-inventory status notes,
   the Coverage Notes section) are the right place to say "skipped by
   configuration for this tenant" rather than silently making that
   evidence type disappear with no explanation — this project's existing
   rule is "no silent caps," and a skip flag is exactly that kind of cap.

4. **Report/control-mapping side: mostly free.** `_present_evidence_keys()`
   in the exporter already detects each evidence type by checking whether
   any device/user actually has non-`None` data for it. If a flag simply
   results in that data never being populated, the corresponding
   "Satisfies:" badges, domain-coverage entries, and table columns
   correctly stop claiming that evidence exists — without needing any
   changes to `control_mapping.py` or the exporter's evidence-detection
   logic itself. The scorer needs no changes either: dimensions already
   return `None` when data isn't present, for any reason.

## Bottom line

- Fix installed-software and BitLocker escrow first — both have a
  credible bulk path, and the software one reuses a mechanism already
  built and proven in this codebase.
- Add `$batch` support to `GraphClient` as the general-purpose fix for
  group membership and auth method detail — it's the one change that
  helps both at once and doesn't depend on finding a report Microsoft may
  not expose.
- Leave Defender health and ownership type alone until each gets its own
  short discovery pass (network-trace the admin center, same as firewall
  status), rather than guessing a report name or risking the shared
  `$select` a third time.
- An enrichment opt-out flag is a real, separable follow-up — it doesn't
  block or depend on any of the above, and can land per-feature using the
  `asset_scope` config pattern already established in this project.
