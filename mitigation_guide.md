# RedSun — Windows Admin Mitigation Guide

**Date:** 2026-04-18 | **Severity:** Critical | **Affected OS:** Windows 10/11, Server 2019/2022

---

## What You Are Defending Against

RedSun is a local privilege escalation exploit that chains Windows Defender's VSS snapshot behavior, Cloud Files placeholders, batch oplocks, and directory junctions to write an arbitrary executable into `C:\Windows\System32` and execute it as SYSTEM. It requires only standard user privileges to run.

---

## Immediate Mitigations (Do These First)

### 1. Block the Cloud Files API for non-Microsoft applications
The exploit relies on `CfRegisterSyncRoot` to create fake file placeholders. You can audit and restrict which applications register sync roots.

```
Registry path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\
Action: Review entries. Any entry not from Microsoft, OneDrive, Dropbox, or your approved sync clients should be investigated and removed.
```

### 2. Enable and monitor Sysmon with the following minimum event coverage
Install Sysmon (from Sysinternals) if not already deployed and ensure these event IDs are active:

| Event ID | What It Catches |
|----------|----------------|
| 17/18 | Named pipe creation — catches `\pipe\REDSUN` |
| 11 | File creation — catches System32 writes and Temp activity |
| 12/13 | Registry — catches SyncRootManager changes |
| 1 | Process creation — catches anomalous TieringEngineService launches |

### 3. Alert on writes to TieringEngineService.exe
This file should never be written by a non-Windows-Update process. Add a file integrity monitoring rule or Sysmon rule for:
```
C:\Windows\System32\TieringEngineService.exe
```
Any write from a process not in `C:\Windows\SoftwareDistribution\` or `TiWorker.exe` is an incident.

### 4. Restrict junction point creation in %TEMP%
Group Policy → Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment:  
**"Create symbolic links"** — restrict to Administrators only.  
This does not fully block the exploit (it uses `DeviceIoControl` directly) but raises the bar.

---

## Medium-Term Hardening

### 5. Enable Windows Defender Attack Surface Reduction rules
Ensure these ASR rules are set to **Block** (not Audit):
- `Block process creations originating from PSExec and WMI commands` — GUID: `d1e49aac-8f56-4280-b9ba-993a6d77406c`
- `Block untrusted and unsigned processes that run from USB` — GUID: `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`
- `Use advanced protection against ransomware` — GUID: `c1db55ab-c21a-4637-bb3f-a12568109d35`

### 6. Disable Storage Tiers Management COM server if not needed
If your environment does not use Windows Storage Spaces tiering, you can disable the COM server:

```powershell
# Check if Storage Tiers is in use before disabling
Get-StorageTier | Select-Object FriendlyName, MediaType

# If not in use, disable the service
Set-Service -Name "StorSvc" -StartupType Disabled
Stop-Service -Name "StorSvc" -Force
```

### 7. Audit VSS snapshot creation frequency
Unexpected VSS snapshots created outside backup windows should alert. Configure WMI event subscription or use your SIEM to alert on `EventID 8193` (VSS) during non-backup hours.

### 8. Monitor named pipe creation
Any process creating `\\.\pipe\REDSUN` should immediately trigger an incident response. Add this as a high-confidence alert in your SIEM using Sysmon Event ID 17.

---

## Detection Summary

Deploy the accompanying Sigma rules (`Sigma_Rules_RedSun.yml`) to your SIEM. Priority order:

| Priority | Rule | False Positive Risk |
|----------|------|-------------------|
| 1 | Named pipe REDSUN | None |
| 2 | TieringEngineService.exe written by non-Update | Very low |
| 3 | TieringEngineService.exe launched outside svchost | None |
| 4 | SyncRootManager — SERIOUSLYMSFT provider | None |
| 5 | Conhost launched by SYSTEM in user session | Low |

Use the accompanying `detect_redsun.ps1` script to sweep endpoints for existing compromise indicators.

---

## If You Believe a System Is Compromised

1. Isolate the host from the network immediately.
2. Run `detect_redsun.ps1` from a clean admin context.
3. Check `C:\Windows\System32\TieringEngineService.exe` hash against known-good.
4. Review Sysmon logs for pipe creation, junction events, and VSS activity in the 24 hours prior.
5. Re-image if compromise is confirmed — do not attempt to clean in-place.
