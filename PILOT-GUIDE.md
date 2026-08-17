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
python run_assessment.py --demo
```

You should see the on-prem demo path run to completion with no errors.
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

Add an on-prem entry to your `tenants.yaml` with your test DC's details:

```yaml
clients:
  - tenant_key: testdc
    display_name: "Test Domain Controller"
    planes: [onprem]
    domain_config:
      domain_controller: "dc01.test.local"
      base_dn: "DC=test,DC=local"
      bind_dn: "svc-cmmc@test.local"
      secret_ref: "PILOT_AD_BIND_SECRET"
```

Set the bind password:

```powershell
$env:PILOT_AD_BIND_SECRET = "the real password"
python run_assessment.py --tenant testdc
```

**Watch for:**
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

### Set up a multi-tenant app registration

1. In **your own** Entra tenant (e.g. Tenguard), register a new application
   (or use an existing one like `cmmc-toolkit-pilot`).
2. Under **Authentication → Supported account types**, set it to
   **"Multiple Entra ID tenants"** (multi-tenant).
3. Note the **Application (client) ID** and the **Directory (tenant) ID**.
4. Create a client secret under **Certificates & secrets** — copy the value
   immediately, it's not retrievable later.
5. Under **API permissions**, add these **Application** (not Delegated)
   permissions for Microsoft Graph:
   - `User.Read.All`
   - `Group.Read.All`
   - `AuditLog.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
   - `DeviceManagementConfiguration.Read.All`
   - `DeviceManagementApps.Read.All`
   - `DeviceManagementRBAC.Read.All`
   - `RoleManagement.Read.Directory`
   - `Reports.Read.All`
   - `Policy.Read.All`
   - `BitlockerKey.ReadBasic.All`
   - `Application.Read.All`
   - `SecurityAlert.Read.All`
   - `UserAuthenticationMethod.Read.All`
6. Click **Grant admin consent** for your own tenant.

For MDE (Defender for Endpoint) collectors, also add these permissions
under **APIs my organization uses → WindowsDefenderATP**:
   - `Alert.Read.All`
   - `Vulnerability.Read.All`
   - `SecurityRecommendation.Read.All`
   - `SecurityConfiguration.Read.All`
   - `SecurityBaselinesAssessment.Read.All`
   - `RemediationTasks.Read.All`

### Configure tenants.yaml

Fill in your `tenants.yaml` with the shared app and test tenant:

```yaml
app:
  client_id: "your-app-client-id"
  secret_ref: "TENGUARD_GRAPH_CLIENT_SECRET"

clients:
  - tenant_key: tenguard
    display_name: "Tenguard Security"
    tenant_id: "your-tenant-id"
```

Set the secret and run:

```powershell
$env:TENGUARD_GRAPH_CLIENT_SECRET = "the real client secret"
python run_assessment.py --tenant tenguard
```

**Watch for:**
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
- MDE collectors will only return data if Defender for Endpoint is actually
  deployed in the tenant. If not, they'll log warnings but not fail the
  overall assessment.

### Testing with a second (client) tenant

This is the real multi-tenant test. Get a second tenant ID (your M365 dev
tenant, or a client who's agreed to test):

1. Have the second tenant's admin visit:
   ```
   https://login.microsoftonline.com/{second-tenant-id}/adminconsent?client_id={your-app-client-id}
   ```
2. Add them to `tenants.yaml`:
   ```yaml
     - tenant_key: testclient
       display_name: "Test Client"
       tenant_id: "second-tenant-id"
   ```
3. Run: `python run_assessment.py --tenant testclient`

If the consent URL works and the assessment runs, your multi-tenant setup
is validated — every future client follows the same two-step process.

---

## Reporting results back

For anything that doesn't work as expected, the most useful thing to paste
back is: the exact error message/traceback, which collector it came from,
and whether you were running elevated (for on-prem) or had granted admin
consent (for cloud). That's usually enough to diagnose without needing to
see the environment itself.
