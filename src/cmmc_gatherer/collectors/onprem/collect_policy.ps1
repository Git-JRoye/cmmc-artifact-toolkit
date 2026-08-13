<#
.SYNOPSIS
    Collects Windows security policy configuration for the CMMC gatherer.
.DESCRIPTION
    Emits a single JSON object to stdout: { "policies": [...], "collection_errors": [...] }.
    Covers four areas, each wrapped independently so one failing section never
    aborts the rest:
      1. Password / account lockout policy  (via secedit /export)
      2. UAC settings                       (registry, HKLM Policies\System)
      3. Audit policy, CMMC-relevant categories only (via auditpol /get /r)
      4. Applied Group Policy Objects, name list only (via gpresult /r)

    #4 is intentionally a lightweight "which GPOs applied" list, not a full
    Resultant Set of Policy parse — that's a documented gap, not an oversight;
    full RSOP parsing is brittle and a reasonable Phase-3 enhancement.
.NOTES
    secedit/UAC/audit sections need only standard user read where permitted;
    an elevated session gets the most complete results.
#>

$ErrorActionPreference = 'Stop'
$errors = @()
$policies = @()
$nowUtc = (Get-Date).ToUniversalTime().ToString('o')

function Try-Section {
    param([scriptblock]$Body, [string]$Name)
    try { & $Body }
    catch { $script:errors += "$Name`: $($_.Exception.Message)"; return $null }
}

# --- 1. Password / lockout policy (secedit) ---
Try-Section -Name 'password_policy' -Body {
    $tmp = Join-Path $env:TEMP "secedit_export_$PID.cfg"
    secedit /export /cfg $tmp /quiet | Out-Null
    $cfg = Get-Content $tmp -ErrorAction Stop
    Remove-Item $tmp -ErrorAction SilentlyContinue

    $numeric = @{
        MinimumPasswordLength         = 'Minimum password length (characters)'
        PasswordHistorySize           = 'Password history size (remembered passwords)'
        MaximumPasswordAge            = 'Maximum password age (days)'
        MinimumPasswordAge            = 'Minimum password age (days)'
        LockoutBadCount               = 'Account lockout threshold (bad attempts)'
        ResetLockoutCount             = 'Reset lockout counter after (minutes)'
        LockoutDuration                = 'Account lockout duration (minutes)'
    }
    $boolean = @{
        PasswordComplexity             = 'Password must meet complexity requirements'
        ClearTextPassword              = 'Store passwords using reversible encryption'
        RequireLogonToChangePassword   = 'User must log on to change password'
        ForceLogoffWhenHourExpire      = 'Force logoff when logon hours expire'
    }

    foreach ($line in $cfg) {
        if ($line -match '^\s*([A-Za-z]+)\s*=\s*(-?\d+)\s*$') {
            $key = $Matches[1]; $val = [int]$Matches[2]
            if ($numeric.ContainsKey($key)) {
                $policies += [pscustomobject]@{
                    policy_name = $key; policy_type = 'Local Security Policy'
                    status = 'Configured'; target = 'Computer'
                    value = "$val"; description = $numeric[$key]; last_applied = $null
                }
            } elseif ($boolean.ContainsKey($key)) {
                $policies += [pscustomobject]@{
                    policy_name = $key; policy_type = 'Local Security Policy'
                    status = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
                    target = 'Computer'; value = $null
                    description = $boolean[$key]; last_applied = $null
                }
            }
        }
    }
}

# --- 2. UAC settings (registry) ---
Try-Section -Name 'uac' -Body {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uacKeys = @{
        EnableLUA                     = 'User Account Control (UAC) enabled'
        ConsentPromptBehaviorAdmin    = 'UAC prompt behavior for administrators'
        ConsentPromptBehaviorUser     = 'UAC prompt behavior for standard users'
        PromptOnSecureDesktop          = 'UAC uses the secure desktop for prompts'
        FilterAdministratorToken      = 'Admin Approval Mode for built-in Administrator'
    }
    if (Test-Path $path) {
        $reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $uacKeys.Keys) {
            $val = $reg.$key
            if ($null -ne $val) {
                $policies += [pscustomobject]@{
                    policy_name = $key; policy_type = 'UAC (Local Policy)'
                    status = if ($val -eq 1) { 'Enabled' } elseif ($val -eq 0) { 'Disabled' } else { 'Configured' }
                    target = 'Computer'; value = "$val"
                    description = $uacKeys[$key]; last_applied = $null
                }
            }
        }
    }
}

# --- 3. Audit policy, CMMC-relevant categories only ---
Try-Section -Name 'audit_policy' -Body {
    $relevantCategories = @('Logon/Logoff', 'Account Management', 'Policy Change', 'Privilege Use', 'Account Logon')
    foreach ($cat in $relevantCategories) {
        try {
            $csv = auditpol /get /category:"$cat" /r 2>$null | ConvertFrom-Csv
            foreach ($row in $csv) {
                if ($row.Subcategory) {
                    $policies += [pscustomobject]@{
                        policy_name = $row.Subcategory; policy_type = 'Audit Policy'
                        status = $row.'Inclusion Setting'; target = 'Computer'
                        value = $null; description = "Audit category: $cat"; last_applied = $null
                    }
                }
            }
        } catch {
            $script:errors += "audit_policy category '$cat': $($_.Exception.Message)"
        }
    }
}

# --- 4. Applied GPOs (name list only — see script header) ---
Try-Section -Name 'applied_gpos' -Body {
    $raw = gpresult /r /scope:computer 2>$null
    $names = @()
    $inSection = $false
    foreach ($line in $raw) {
        if ($line -match 'Applied Group Policy Objects') { $inSection = $true; continue }
        if ($inSection) {
            if ($line -match '^\s*-+\s*$' -or $line -match '^\s*$') { continue }
            if ($line -match '^\s{2,}\S') { $names += $line.Trim() }
            else { break }
        }
    }
    $lastAppliedLine = $raw | Where-Object { $_ -match 'Last time Group Policy was applied' } | Select-Object -First 1
    $lastApplied = if ($lastAppliedLine) { ($lastAppliedLine -split ':\s*', 2)[1].Trim() } else { $null }

    $policies += [pscustomobject]@{
        policy_name = 'Applied Group Policy Objects'; policy_type = 'Group Policy'
        status = if ($names.Count -gt 0) { 'Applied' } else { 'None Applied' }
        target = 'Computer'; value = ($names -join '; ')
        description = 'Name list of GPOs applied to this computer (not a full RSOP parse)'
        last_applied = $lastApplied
    }
}

[pscustomobject]@{
    policies          = $policies
    collection_errors = $errors
} | ConvertTo-Json -Depth 6 -Compress
