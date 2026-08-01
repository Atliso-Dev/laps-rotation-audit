<#
.SYNOPSIS
    Atliso-LapsRotationAudit.ps1 - Audit and force Windows LAPS password rotation.

.DESCRIPTION
    Windows LAPS can report as compliant in Intune while the local admin password
    hasn't actually rotated in months. This script confirms whether a successful
    password backup was logged inside the expected window, and if not, forces a
    rotation with Reset-LapsPassword.

    Detection signal: event 10029 (Entra ID backup) or 10018 (Active Directory backup)
    in the Microsoft-Windows-LAPS/Operational channel, logged inside
    PasswordAgeDays + GraceDays. It also flags event 10005 (policy processing failed),
    which means rotation is actively failing rather than just late.

    Runs audit-only by default (-WhatIf $true). Set -WhatIf $false to force rotation.

    Intune usage: deploy as a Remediation. The detection half exits 1 when no
    successful backup is confirmed inside the window. Run as SYSTEM, 64-bit.

.NOTES
    MIT licensed. Free to use and modify.
    Reconstructed from the published Atliso article spec - lab-test before fleet rollout.
    Tested target: Windows 10/11 with Windows LAPS, PowerShell 5.1+.
#>

[CmdletBinding()]
param(
    # Where this device backs up its LAPS password. Match your Intune LAPS policy.
    # "EntraID" for Entra-joined and hybrid devices onboarded through Intune,
    # "ActiveDirectory" for on-prem devices still managed by the GPO path.
    [ValidateSet("EntraID", "ActiveDirectory")]
    [string]$BackupDestination = "EntraID",

    # Your Intune LAPS policy's Password Age Days value. Detection uses this as
    # the baseline, not a guess.
    [int]$PasswordAgeDays = 30,

    # Days of slack on top of PasswordAgeDays before "hasn't rotated yet" becomes
    # "rotation is broken". Keep this small.
    [int]$GraceDays = 2,

    # $true reports only. $false actually calls Reset-LapsPassword.
    [bool]$WhatIf = $true,

    [string]$LogPath = (Join-Path $env:LOCALAPPDATA "Atliso\LapsRotationAudit.log")
)

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction Stop
    } catch { }
    Write-Output $line
}

# ── Preconditions ───────────────────────────────────────────────────────────────
if (-not (Get-Command Reset-LapsPassword -ErrorAction SilentlyContinue)) {
    Write-Log "Windows LAPS cmdlets not available on this device. Check the LAPS install/policy." "WARN"
    exit 1
}

$logName = 'Microsoft-Windows-LAPS/Operational'
$eventId = if ($BackupDestination -eq 'EntraID') { 10029 } else { 10018 }
$cutoff  = (Get-Date).AddDays(-($PasswordAgeDays + $GraceDays))

Write-Log "Run start. Destination=$BackupDestination successEventId=$eventId window=$($PasswordAgeDays + $GraceDays)d WhatIf=$WhatIf"

# Surface active failures separately from "just late". Event 10005 means policy
# processing is failing, which no rotation nudge will fix.
try {
    $failures = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        Id        = 10005
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction Stop
} catch { $failures = $null }

if ($failures) {
    Write-Log "Event 10005 (LAPS policy processing failed) logged $($failures.Count) time(s) in the last 24h. Rotation is actively failing, not just late. Run Get-LapsDiagnostics before trusting any remediation." "WARN"
}

# ── Detection: was a successful backup logged inside the window? ─────────────────
# Get-WinEvent throws instead of returning empty when nothing matches, so wrap it.
try {
    $confirmed = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        Id        = $eventId
        StartTime = $cutoff
    } -ErrorAction Stop
} catch { $confirmed = $null }

if ($confirmed) {
    Write-Log "Backup confirmed by event $eventId within the window. Rotation is healthy."
    exit 0
}

Write-Log "No confirmed LAPS backup (event $eventId) inside the window." "WARN"

if ($WhatIf) {
    Write-Log "WhatIf is on - reporting only, no rotation forced. Re-run with -WhatIf `$false to force it."
    exit 1
}

# ── Remediation: force rotation ─────────────────────────────────────────────────
Write-Log "Forcing rotation with Reset-LapsPassword."
try {
    Reset-LapsPassword -ErrorAction Stop
} catch {
    Write-Log "Reset-LapsPassword failed: $($_.Exception.Message)" "ERROR"
    exit 1
}

# Reset-LapsPassword hands off to LAPS' own background processing, it doesn't
# rotate the password itself. Windows LAPS wakes up hourly on a fixed,
# non-configurable cycle - there's no scheduled task to nudge and no way to
# make it faster than that.
Write-Log "Reset-LapsPassword called. Expect the new password within the next hourly cycle."
exit 0
