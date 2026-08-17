# Getting Started — Installing the CMMC Artifact Toolkit

**Start here if this is your first time with this repo.** This covers
downloading and installing the tool itself. Once it's installed, go to
`USER_GUIDE_SINGLE_ORG.md` (assessing your own organization) or
`USER_GUIDE_MSP.md` (assessing multiple clients) for how to configure and
run it against a real environment.

**This is a living document** — update it if a step here stops matching
reality.

---

## What you need on your computer first

- **Windows 10/11 or Windows Server.** Required — this tool collects
  Windows-specific security data (registry, Local Security Policy, Event
  Log) via PowerShell. It won't run its on-prem collection on macOS/Linux.
- **Python 3.10 or newer.**
- **Git** — optional. Only needed if you clone the repo with `git`
  instead of downloading a ZIP from GitHub (both work equally well).

You do **not** need to change your PowerShell execution policy. The tool
invokes PowerShell itself with `-ExecutionPolicy Bypass` for its own
script calls only — it doesn't require or make any changes to your
system's global execution policy setting.

---

## Step 1 — Install Python (skip if you already have it)

Check first:

```powershell
python --version
```

If that fails or shows a version older than 3.10:

1. Go to [python.org/downloads](https://www.python.org/downloads/) and
   download the latest Windows installer.
2. Run it. **Check the box that says "Add python.exe to PATH"** at the
   bottom of the first installer screen — this is easy to miss and
   everything below depends on it.
3. Close and reopen your terminal, then confirm:

```powershell
python --version
pip --version
```

---

## Step 2 — Get the code onto your machine

**Option A — with Git:**

```powershell
git clone https://github.com/Git-JRoye/cmmc-artifact-toolkit.git
cd cmmc-artifact-toolkit
```

**Option B — without Git:**

1. On the GitHub repo page, click the green **Code** button → **Download ZIP**.
2. Extract the ZIP somewhere you'll remember (e.g. `Documents\cmmc-artifact-toolkit`).
3. Open PowerShell and `cd` into that extracted folder.

Either way, you should now be sitting in a folder containing `run_assessment.py`,
`requirements.txt`, `tenants.example.yaml`, and a `src\` folder.

---

## Step 3 — Install the Python dependencies

From inside that folder:

```powershell
pip install -r requirements.txt
```

If `pip` isn't recognized as a command, use:

```powershell
python -m pip install -r requirements.txt
```

---

## Step 4 — Verify the install actually works (no real environment needed yet)

This command reads the **example** config file (which only contains fake,
placeholder client data — Acme Corporation, Globex, etc.) and validates
it. It makes no network calls and touches no real credentials — it's a
safe, side-effect-free way to confirm the install itself is working
before you configure anything real:

```powershell
python run_assessment.py --config tenants.example.yaml --list
```

You should see output like:

```
5 tenant(s) configured in tenants.example.yaml:
  acme                 Acme Corporation               [cloud]
  globex               Globex Corporation              [onprem]
  initech              Initech LLC                     [hybrid]
  wayne_enterprises     Wayne Enterprises               [cloud]
  stark_industries     Stark Industries               [cloud]
```

If you see that (with no `INVALID CONFIG` errors), the installation is
working correctly.

---

## Step 5 — Set up your own environment

Copy the example config to your own, real one (gitignored — this is
where your actual environment's details live, never committed):

```powershell
cp tenants.example.yaml tenants.yaml
```

The example file shows a multi-tenant MSP setup with a shared app
registration. For a single organization, you only need one entry under
`clients:` — see `USER_GUIDE_SINGLE_ORG.md`.

Now go to:

- **`USER_GUIDE_SINGLE_ORG.md`** if you're assessing one organization
  (your own, or a single client), or
- **`USER_GUIDE_MSP.md`** if you're managing multiple client tenants

for exactly what to fill in and how to run your first real assessment.

---

*Last updated: install flow unchanged since this doc was created — still
accurate as of the ownership-type/Collection Health features. If a step
here stops matching what actually happens, fix this doc, not just the
tool.*
