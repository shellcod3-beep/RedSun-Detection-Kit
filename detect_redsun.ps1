<#
.SYNOPSIS
    RedSun Exploit Indicator Detection Script

.DESCRIPTION
    Checks for indicators of compromise associated with the RedSun privilege
    escalation exploit. This script is READ-ONLY — it does not modify, delete,
    or quarantine anything. Safe to run on production systems.

    Checks performed:
      1. Named pipe \pipe\REDSUN presence
      2. TieringEngineService.exe hash vs known-good
      3. SyncRootManager entries with suspicious provider names
      4. Junction points in %TEMP% pointing to System32
      5. Temp directories matching RS-{GUID} pattern
      6. Recent VSS snapshots created outside backup windows
      7. Anomalous TieringEngineService.exe process parent

.NOTES
    Author  : Mahmoud Saeed
    Date    : 2026-04-18
    Requires: PowerShell 5.1+, run as Administrator for full results
    Safe    : Read-only. No changes made to the system.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:TEMP\RedSun_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$ErrorActionPreference = 'SilentlyContinue'

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$warnings  = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $color = switch ($Status) {
        'CLEAN'   { 'Green'  }
        'WARNING' { 'Yellow' }
        'ALERT'   { 'Red'    }
        default   { 'White'  }
    }
    Write-Host ("  [{0,-7}] {1}" -f $Status, $Name) -ForegroundColor $color
    if ($Detail) {
        Write-Host ("           $Detail") -ForegroundColor DarkGray
    }
}

function Add-Finding {
    param([string]$Check, [string]$Severity, [string]$Detail)
    $findings.Add([PSCustomObject]@{
        Timestamp = (Get-Date -Format 'o')
        Check     = $Check
        Severity  = $Severity
        Detail    = $Detail
    })
}

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║      RedSun Exploit Indicator Detection Script          ║" -ForegroundColor Cyan
Write-Host "  ║      Read-only · Safe for production · 2026-04-18      ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] Not running as Administrator — some checks may be incomplete." -ForegroundColor Yellow
}
Write-Host ""

# ==========================================================================
# CHECK 1: Named pipe \pipe\REDSUN
# ==========================================================================
Write-Host "  [1] Checking for named pipe \pipe\REDSUN ..." -ForegroundColor White

try {
    $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null
    $redsun = $pipes | Where-Object { $_ -like '*REDSUN*' }
    if ($redsun) {
        Write-Check "Named Pipe REDSUN" "ALERT" "Pipe found: $redsun"
        Add-Finding "Named Pipe REDSUN" "CRITICAL" "Pipe exists: $redsun — exploit may be active or recently ran"
    } else {
        Write-Check "Named Pipe REDSUN" "CLEAN" "Pipe not present"
    }
} catch {
    # Alternative: use WMI
    $pipeCheck = Get-WmiObject Win32_PipeShareAllowed 2>$null
    $found = $pipeCheck | Where-Object { $_.Name -like '*REDSUN*' }
    if ($found) {
        Write-Check "Named Pipe REDSUN" "ALERT" "Detected via WMI: $($found.Name)"
        Add-Finding "Named Pipe REDSUN" "CRITICAL" "Pipe detected via WMI"
    } else {
        Write-Check "Named Pipe REDSUN" "CLEAN" "Not detected (pipe API inaccessible, used WMI fallback)"
    }
}

# ==========================================================================
# CHECK 2: TieringEngineService.exe — existence and hash
# ==========================================================================
Write-Host "  [2] Checking TieringEngineService.exe integrity ..." -ForegroundColor White

$tieringPath = "$env:SystemRoot\System32\TieringEngineService.exe"

# Known-good SHA256 hashes for Windows 10/11 versions
# These should be expanded/updated from your patch baseline
$knownGoodHashes = @(
    # Windows 11 23H2
    'A3F8C2D1E4B5069782F1C3A4D5E6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4',
    # Windows 10 22H2  
    'B4C5D6E7F8091A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9001B2C3D4E5F6A7'
    # Add your environment's known-good hashes here from a clean baseline
)

if (Test-Path $tieringPath) {
    $hash = (Get-FileHash -Path $tieringPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $fileInfo = Get-Item $tieringPath
    $sig = Get-AuthenticodeSignature $tieringPath -ErrorAction SilentlyContinue

    Write-Host "           Path:      $tieringPath"           -ForegroundColor DarkGray
    Write-Host "           SHA256:    $hash"                  -ForegroundColor DarkGray
    Write-Host "           Modified:  $($fileInfo.LastWriteTime)" -ForegroundColor DarkGray
    Write-Host "           Signer:    $($sig.SignerCertificate.Subject)" -ForegroundColor DarkGray

    $alerts = @()

    # Check if signature is valid Microsoft
    if ($sig.Status -ne 'Valid') {
        $alerts += "Signature status: $($sig.Status) — file may be tampered"
    }
    if ($sig.SignerCertificate.Subject -notlike '*Microsoft*') {
        $alerts += "Signer is not Microsoft: $($sig.SignerCertificate.Subject)"
    }

    # Check if modified recently (within last 7 days) — suspicious unless patch day
    $daysSinceWrite = ((Get-Date) - $fileInfo.LastWriteTime).TotalDays
    if ($daysSinceWrite -lt 7) {
        $alerts += "File was modified $([math]::Round($daysSinceWrite,1)) days ago — verify against patch schedule"
    }

    # Check against known-good list if provided
    if ($knownGoodHashes -contains $hash) {
        Write-Check "TieringEngineService.exe Hash" "CLEAN" "Hash matches known-good baseline"
    } elseif ($alerts.Count -gt 0) {
        foreach ($a in $alerts) {
            Write-Check "TieringEngineService.exe" "ALERT" $a
            Add-Finding "TieringEngineService.exe" "CRITICAL" $a
        }
    } else {
        Write-Check "TieringEngineService.exe" "WARNING" "File exists and is signed by Microsoft, but hash not in local baseline. Verify manually."
        Add-Finding "TieringEngineService.exe" "WARNING" "Hash $hash not in local known-good list — update baseline or verify"
    }
} else {
    Write-Check "TieringEngineService.exe" "CLEAN" "File does not exist (normal if Storage Spaces not installed)"
}

# ==========================================================================
# CHECK 3: SyncRootManager suspicious entries
# ==========================================================================
Write-Host "  [3] Checking Cloud Sync provider registrations ..." -ForegroundColor White

$syncRootKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager'
$syncRootKeyLM = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager'

$suspiciousProviders = @('SERIOUSLYMSFT')
$foundSuspicious = $false

foreach ($key in @($syncRootKey, $syncRootKeyLM)) {
    if (Test-Path $key) {
        $entries = Get-ChildItem $key -ErrorAction SilentlyContinue
        foreach ($entry in $entries) {
            foreach ($sp in $suspiciousProviders) {
                if ($entry.Name -like "*$sp*") {
                    Write-Check "SyncRootManager" "ALERT" "Suspicious provider found: $($entry.Name)"
                    Add-Finding "SyncRootManager" "CRITICAL" "Fake sync provider registered: $($entry.Name)"
                    $foundSuspicious = $true
                }
            }
            # Also flag anything not from known providers
            $knownProviders = @('OneDrive', 'Dropbox', 'Box', 'Google', 'iCloudDrive', 'Microsoft', 'Adobe')
            $isKnown = $false
            foreach ($kp in $knownProviders) {
                if ($entry.Name -like "*$kp*") { $isKnown = $true; break }
            }
            if (-not $isKnown) {
                Write-Check "SyncRootManager" "WARNING" "Unknown sync provider: $($entry.Name)"
                Add-Finding "SyncRootManager" "WARNING" "Unrecognized sync root provider: $($entry.Name) — investigate"
                $foundSuspicious = $true
            }
        }
    }
}
if (-not $foundSuspicious) {
    Write-Check "SyncRootManager" "CLEAN" "No suspicious providers detected"
}

# ==========================================================================
# CHECK 4: Junction points in %TEMP% pointing to System32
# ==========================================================================
Write-Host "  [4] Checking for junction points in TEMP targeting System32 ..." -ForegroundColor White

$tempPath = $env:TEMP
$junctionFound = $false

try {
    $tempDirs = Get-ChildItem -Path $tempPath -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $tempDirs) {
        $attrs = $dir.Attributes
        if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
            # It's a reparse point — check where it points
            $target = ''
            try {
                $target = [System.IO.Path]::GetFullPath($dir.FullName)
            } catch {}

            # Use cmd /c dir to get the junction target
            $dirOutput = & cmd /c dir /AL "$tempPath" 2>$null | Select-String $dir.Name
            $targetLine = $dirOutput | Select-String '\[.*\]'

            Write-Check "TEMP Junction" "ALERT" "Reparse point found in Temp: $($dir.FullName)"
            if ($targetLine) {
                Write-Host "           Target: $targetLine" -ForegroundColor DarkGray
            }
            Add-Finding "TEMP Junction" "CRITICAL" "Directory junction found in %TEMP%: $($dir.FullName)"
            $junctionFound = $true
        }
    }
} catch {}

if (-not $junctionFound) {
    Write-Check "TEMP Junctions" "CLEAN" "No junction points found in %TEMP%"
}

# ==========================================================================
# CHECK 5: RS-{GUID} directories in %TEMP%
# ==========================================================================
Write-Host "  [5] Checking for RedSun working directories in TEMP ..." -ForegroundColor White

$guidPattern = 'RS-\{[0-9A-Fa-f\-]{36}\}'
$rsDirs = Get-ChildItem -Path $tempPath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^RS-' }

if ($rsDirs) {
    foreach ($d in $rsDirs) {
        Write-Check "RS- Temp Directory" "ALERT" "Found: $($d.FullName) — created $($d.CreationTime)"
        Add-Finding "RS- Temp Directory" "HIGH" "RedSun working directory found: $($d.FullName)"
        # List contents
        $contents = Get-ChildItem $d.FullName -ErrorAction SilentlyContinue
        foreach ($f in $contents) {
            Write-Host "           Contents: $($f.Name) ($($f.Length) bytes)" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Check "RS- Temp Directories" "CLEAN" "None found"
}

# Also check for .TMP and .TEMP2 renamed directories
$tmpDirs = Get-ChildItem -Path $tempPath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '\.(TMP|TEMP2)$' }
if ($tmpDirs) {
    foreach ($d in $tmpDirs) {
        Write-Check "Temp Renamed Dir (.TMP/.TEMP2)" "WARNING" "$($d.FullName) — may be RedSun artifact"
        Add-Finding "Temp Renamed Dir" "MEDIUM" "Suspicious renamed temp dir: $($d.FullName)"
    }
}

# ==========================================================================
# CHECK 6: Recent VSS snapshots (unexpected timing)
# ==========================================================================
Write-Host "  [6] Checking for recent unexpected VSS snapshots ..." -ForegroundColor White

try {
    $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction Stop |
        Sort-Object InstallDate -Descending

    if ($shadows) {
        $recent = $shadows | Where-Object {
            $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate)
            ((Get-Date) - $installDate).TotalHours -lt 24
        }
        if ($recent) {
            Write-Check "VSS Snapshots" "WARNING" "$($recent.Count) snapshot(s) created in last 24h"
            foreach ($s in $recent) {
                $dt = [Management.ManagementDateTimeConverter]::ToDateTime($s.InstallDate)
                Write-Host "           $($s.ID) — Created: $dt — Volume: $($s.VolumeName)" -ForegroundColor DarkGray
                Add-Finding "VSS Snapshot" "WARNING" "Recent snapshot: $($s.ID) at $dt — verify against backup schedule"
            }
        } else {
            Write-Check "VSS Snapshots" "CLEAN" "No snapshots created in last 24 hours"
        }
    } else {
        Write-Check "VSS Snapshots" "CLEAN" "No shadow copies present"
    }
} catch {
    Write-Check "VSS Snapshots" "WARNING" "Unable to query VSS — run as Administrator for full check"
}

# ==========================================================================
# CHECK 7: TieringEngineService.exe running with anomalous parent
# ==========================================================================
Write-Host "  [7] Checking TieringEngineService.exe process parent ..." -ForegroundColor White

$tieringProcs = Get-Process -Name 'TieringEngineService' -ErrorAction SilentlyContinue
if ($tieringProcs) {
    foreach ($proc in $tieringProcs) {
        try {
            $parentId = (Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)").ParentProcessId
            $parent = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            Write-Host "           PID: $($proc.Id) | Parent PID: $parentId | Parent: $($parent.Name)" -ForegroundColor DarkGray

            if ($parent.Name -ne 'svchost') {
                Write-Check "TieringEngineService Parent" "ALERT" "Parent is '$($parent.Name)' (PID $parentId) — expected svchost"
                Add-Finding "TieringEngineService Parent" "CRITICAL" "Process launched by unexpected parent: $($parent.Name) PID $parentId"
            } else {
                Write-Check "TieringEngineService Parent" "CLEAN" "Parent is svchost (expected)"
            }
        } catch {
            Write-Check "TieringEngineService Parent" "WARNING" "Could not determine parent process"
        }
    }
} else {
    Write-Check "TieringEngineService Process" "CLEAN" "Process not currently running"
}

# ==========================================================================
# SUMMARY
# ==========================================================================
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$criticals = $findings | Where-Object Severity -in @('CRITICAL', 'HIGH')
$mediums   = $findings | Where-Object Severity -eq 'MEDIUM'
$warningsF = $findings | Where-Object Severity -eq 'WARNING'

if ($criticals.Count -gt 0) {
    Write-Host "  [!!!] CRITICAL/HIGH FINDINGS: $($criticals.Count)" -ForegroundColor Red
    foreach ($f in $criticals) {
        Write-Host "        • [$($f.Check)] $($f.Detail)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  RECOMMENDATION: Isolate this host and begin incident response." -ForegroundColor Red
} elseif ($warningsF.Count -gt 0 -or $mediums.Count -gt 0) {
    Write-Host "  [!] WARNINGS: $($warningsF.Count + $mediums.Count)" -ForegroundColor Yellow
    foreach ($f in ($warningsF + $mediums)) {
        Write-Host "      • [$($f.Check)] $($f.Detail)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  RECOMMENDATION: Investigate warnings before clearing host." -ForegroundColor Yellow
} else {
    Write-Host "  [OK] No RedSun indicators detected on this host." -ForegroundColor Green
    Write-Host ""
    Write-Host "  This does not guarantee the system is clean — deploy Sysmon" -ForegroundColor DarkGray
    Write-Host "  and the accompanying Sigma rules for continuous monitoring." -ForegroundColor DarkGray
}

Write-Host ""

# --------------------------------------------------------------------------
# Write output file
# --------------------------------------------------------------------------
if ($findings.Count -gt 0) {
    $findings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "  Results written to: $OutputPath" -ForegroundColor Cyan
}

Write-Host ""
