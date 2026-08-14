<#
.SYNOPSIS
    Collects Windows endpoint security posture for the CMMC gatherer.
.DESCRIPTION
    Emits a single JSON object to stdout describing OS, patch level, Defender
    status, firewall state, registered security products, and installed
    software (CM.L2-3.4.1 system-inventory evidence). Every section is
    wrapped in try/catch so one failure never aborts the whole collection —
    the corresponding field is left null and an entry is added to
    "collection_errors". Run locally, or remotely via Invoke-Command (see the
    Python collector).
.NOTES
    Requires PowerShell 5.1+ and (for full data) an elevated session.
    root/SecurityCenter2 exists on client SKUs only, not Windows Server.
#>

$ErrorActionPreference = 'Stop'
$errors = @()

function Try-Section {
    param([scriptblock]$Body, [string]$Name)
    try { & $Body }
    catch { $script:errors += "$Name`: $($_.Exception.Message)"; return $null }
}

# --- OS + identity ---
$os = Try-Section -Name 'os' -Body {
    Get-CimInstance -ClassName Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber
}
$osVersion = if ($os) { "$($os.Caption) (Build $($os.BuildNumber))" } else { $null }

$ipv4 = Try-Section -Name 'ip' -Body {
    (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1 -ExpandProperty IPAddress)
}

# --- Patches / installed updates ---
$updates = Try-Section -Name 'updates' -Body {
    @(Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID)
}
if ($null -eq $updates) { $updates = @() }

# --- Windows Defender ---
$defender = Try-Section -Name 'defender' -Body {
    Get-MpComputerStatus -ErrorAction Stop |
        Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled,
                      AntivirusSignatureLastUpdated
}
$avStatus = if ($defender -and $defender.RealTimeProtectionEnabled) { 'Active' }
            elseif ($defender) { 'Inactive' } else { $null }

# --- Firewall (all three profiles) ---
$fwProfiles = Try-Section -Name 'firewall' -Body {
    @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled)
}
$fwStatus = $null
if ($fwProfiles) {
    $enabledCount = @($fwProfiles | Where-Object { $_.Enabled }).Count
    $fwStatus = if ($enabledCount -eq $fwProfiles.Count) { 'Enabled' }
                elseif ($enabledCount -gt 0) { 'Partial' } else { 'Disabled' }
}

# --- Registered security products (client SKUs only) ---
$secProducts = Try-Section -Name 'security_products' -Body {
    @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object -ExpandProperty displayName)
}
if ($null -eq $secProducts) {
    # Fall back to Defender name if SecurityCenter2 is unavailable (e.g. Server).
    $secProducts = if ($defender -and $defender.AntivirusEnabled) { @('Windows Defender') } else { @() }
}

# --- Installed software inventory (CM.L2-3.4.1: system inventory must
# include software, not just hardware/OS) ---
# Reads the standard Windows uninstall registry hives -- the same source
# Control Panel > Programs and Features / winget list ultimately reads from.
# KNOWN GAPS, stated plainly: this only sees software with a traditional
# uninstall entry -- it will miss most UWP/Microsoft Store apps (different
# registration mechanism entirely) and portable/xcopy-deployed applications
# that never write an uninstall key. That's a real, acceptable limitation
# for a first pass at this evidence requirement, not a silent gap.
$software = Try-Section -Name 'software' -Body {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
            Select-Object @{N = 'name'; E = { $_.DisplayName } },
                          @{N = 'version'; E = { $_.DisplayVersion } },
                          @{N = 'publisher'; E = { $_.Publisher } }
    }
    @($apps | Sort-Object name -Unique)
}
if ($null -eq $software) { $software = @() }

[pscustomobject]@{
    hostname           = $env:COMPUTERNAME
    ip_address         = $ipv4
    os_version         = $osVersion
    installed_updates  = $updates
    security_products  = $secProducts
    firewall_status    = $fwStatus
    antivirus_status   = $avStatus
    metadata           = @{
        defender_realtime   = if ($defender) { [bool]$defender.RealTimeProtectionEnabled } else { $null }
        defender_sigs_updated = if ($defender) { "$($defender.AntivirusSignatureLastUpdated)" } else { $null }
        firewall_profiles   = $fwProfiles
        installed_software  = $software
        collected_utc       = (Get-Date).ToUniversalTime().ToString('o')
        collection_errors   = $errors
    }
} | ConvertTo-Json -Depth 6 -Compress
