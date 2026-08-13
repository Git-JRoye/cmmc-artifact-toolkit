# Pilot Testing Guide

Everything built so far has been syntax- and logic-verified, never run
against a real environment. This guide walks through validating it against
one real on-prem test box and one real M365 test tenant before any of this
touches actual client data.

Run this **from a Windows machine** (PowerShell collectors require it).

---

## Step 0 — sanity-check the harness itself

Before pointing anything at a real environment, confirm the harness runs at
all using demo data:

```powershell
$env:CMMC_DEMO="1"
python pilot_test.py
```

You should see two things run to completion with no errors (well — one
"no profiles configured" note, since neither profile is filled in yet).
If this fails, something's wrong with the base install (`pip install -r
requirements.txt`), not with any collector — fix that first.

---

## Part A — On-prem pilot

### What you need
- One Windows test machine you can run PowerShell on (a VM is fine — doesn't
  need to be a server or domain-joined for the endpoint/event-log/policy
  collectors specifically).
- **If you also want to test AD**: a test domain controller. If you don't
  have one handy, it's fine to pilot endpoint/event-log/policy first and
  test AD later once you stand one up — those three don't need a domain.

### Test each collector individually first

Before running the full orchestrator, run each on-prem collector alone so a
failure is easy to isolate. From the repo root:

```powershell
python -c "import sys; sys.path.insert(0, 'src'); from cmmc_gatherer.collectors.onprem.endpoint_collector import EndpointCollector; import json; r = EndpointCollector().collect(); print(len(r), 'endpoint(s)'); print(r[0] if r else 'EMPTY')"
```

Repeat the same pattern for event log and policy (swap the import and class
name). **Watch for:**
- Does it return data at all, or an empty list? An empty list with no error
  logged is suspicious — check the console output above it for `WARNING`/
  `ERROR` lines from the collector (logging is on by default in this script).
- Do the field values look real? (Actual hostname, actual OS version, actual
  hotfix IDs — not anything resembling the demo placeholders like
  `WORKSTATION-001`.)
- For the event log and policy collectors specifically: if you're not
  running PowerShell elevated, expect some `collection_errors` entries about
  access — that's the script correctly reporting a permissions gap, not a
  bug. Re-run elevated to get the fuller picture.

### Test AD (if you have a test DC)

Fill in `ONPREM_PROFILE` in `pilot_test.py` with your test DC's hostname,
base DN, and a bind account. Set the bind password as an environment
variable matching `secret_ref`:

```powershell
$env:PILOT_AD_BIND_PASSWORD = "the real password"
```

Then run `python pilot_test.py`. **Watch for:**
- A successful LDAP bind (if it fails, you'll see the `ldap3` error message
  directly — usually a wrong port/SSL setting or bad credentials).
- Users, groups, and computers all returning non-zero counts.
- Spot-check one real user's `group_memberships` — does it list real DNs of
  groups that user is actually in?
- Spot-check `isStale`/`disabled` on an account you know the real status of.

---

## Part B — Cloud pilot

### What you need
A **Microsoft 365 Developer Program** tenant is the easiest way to get a
free, disposable test tenant with sample users/groups already populated —
sign up at the Microsoft 365 developer site if you don't already have one
set aside for testing. Do not use a production client tenant for this.

### Set up an app registration in the test tenant
1. In the test tenant's Entra admin center, register a new application.
2. Note the **Application (client) ID** and the **Directory (tenant) ID**.
3. Create a client secret under **Certificates & secrets** — copy the value
   immediately, it's not retrievable later.
4. Under **API permissions**, add these **Application** (not Delegated)
   permissions for Microsoft Graph:
   - `User.Read.All`
   - `Group.Read.All`
   - `AuditLog.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
5. Click **Grant admin consent** for the tenant — without this step, every
   call will fail with a permissions error regardless of the permissions
   being listed.

### Fill in the harness
In `pilot_test.py`, uncomment and fill in `CLOUD_PROFILE` with the tenant ID,
client ID, and `national_cloud` (leave as `COMMERCIAL` unless your test
tenant is specifically GCC High). Set the secret:

```powershell
$env:PILOT_GRAPH_CLIENT_SECRET = "the real client secret"
```

Run `python pilot_test.py`. **Watch for:**
- A successful token acquisition (an MSAL auth failure will show the actual
  `error`/`error_description` from Entra directly — common causes: wrong
  tenant/client ID, secret expired or mistyped, or admin consent not granted
  yet).
- Real users and groups coming back with plausible `displayName`/
  `userPrincipalName` values.
- If the test tenant has **zero enrolled Intune devices**, the Intune
  collector will correctly return an empty list with no error — that's
  expected, not a bug. Enroll one test device if you want to validate that
  path too.

---

## Reporting results back

For anything that doesn't work as expected, the most useful thing to paste
back is: the exact error message/traceback, which collector it came from,
and whether you were running elevated (for on-prem) or had granted admin
consent (for cloud). That's usually enough to diagnose without needing to
see the environment itself.
