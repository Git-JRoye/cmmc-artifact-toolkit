<#
.SYNOPSIS
    Collects CMMC-relevant entries from the Windows Security event log.
.DESCRIPTION
    Emits a single JSON object to stdout: { "events": [...], "collection_errors": [...] }.
    Each event's EventData is parsed generically from the event's XML representation
    (Data elements keyed by Name), so this works across event IDs without hardcoding
    per-event-type field extraction.
.PARAMETER EventIds
    Comma-separated list of event IDs to collect. Defaults to a CMMC-relevant set:
    logon/logoff (4624/4625/4634/4647), account management (4720/4722/4725/4738/4740/4767),
    privileged group membership changes (4728/4732/4756), special/privileged logon (4672),
    audit policy changes (4719), and object/handle privilege use (4670).
.PARAMETER LookbackHours
    How far back to search. Default 168 (7 days).
.PARAMETER MaxEvents
    Cap on returned events, to bound output size on noisy hosts. Default 2000.
.NOTES
    Requires read access to the Security log — typically an elevated/admin session,
    or membership in the "Event Log Readers" group for read-only collection.
#>

param(
    [string]$EventIds = "4624,4625,4634,4647,4720,4722,4725,4728,4732,4738,4740,4756,4767,4672,4719,4670",
    [int]$LookbackHours = 168,
    [int]$MaxEvents = 2000
)

$ErrorActionPreference = 'Stop'
$errors = @()
$ids = $EventIds -split ',' | ForEach-Object { [int]$_.Trim() }
$startTime = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours)

function Get-EventDataHash {
    param($Event)
    $hash = @{}
    try {
        [xml]$xml = $Event.ToXml()
        $dataNodes = $xml.Event.EventData.Data
        if ($dataNodes) {
            foreach ($node in $dataNodes) {
                if ($node.Name) { $hash[$node.Name] = $node.'#text' }
            }
        }
    } catch {
        # Some providers don't emit structured EventData — leave hash empty rather than fail the event.
    }
    return $hash
}

$events = @()
try {
    $raw = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $ids
        StartTime = $startTime
    } -MaxEvents $MaxEvents -ErrorAction Stop

    foreach ($e in $raw) {
        $data = Get-EventDataHash -Event $e
        $user = $null
        foreach ($key in @('TargetUserName', 'SubjectUserName')) {
            if ($data.ContainsKey($key) -and $data[$key] -and $data[$key] -ne '-') {
                $user = $data[$key]
                break
            }
        }

        $message = $null
        try { $message = $e.Message } catch { $message = "(message unavailable for provider)" }

        $events += [pscustomobject]@{
            event_id   = $e.Id
            source     = $e.ProviderName
            timestamp  = $e.TimeCreated.ToUniversalTime().ToString('o')
            message    = $message
            level      = $e.LevelDisplayName
            computer   = $e.MachineName
            user       = $user
            event_data = $data
        }
    }
} catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
    $errors += "Security log not found on this host"
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        # Get-WinEvent throws a terminating error when zero events match
        # the filter — that's a legitimate outcome (nothing in this
        # lookback window matched), not a collection failure. Leave
        # $events empty and don't record it as an error.
    } else {
        # Common case: access denied when not elevated / not in Event Log Readers.
        $errors += "Get-WinEvent failed: $($_.Exception.Message)"
    }
}

[pscustomobject]@{
    events            = $events
    collection_errors = $errors
} | ConvertTo-Json -Depth 8 -Compress
