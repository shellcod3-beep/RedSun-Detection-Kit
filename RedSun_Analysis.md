# RedSun Exploit — Analysis

**Analyst:** Shellcod3  
**Date:** 2026-04-18  
**Severity:** Critical — Local Privilege Escalation to SYSTEM  

---

## What This Exploit Does — Simple Explanation

This is a **Windows privilege escalation exploit** that abuses Windows Defender's own quarantine behavior to plant a malicious executable inside `System32`. It is a TOCTOU (Time-Of-Check Time-Of-Use) race condition chained with several Windows subsystems.

---

## 1. What Vulnerability Does It Abuse?

It chains four Windows behaviors that are each legitimate in isolation:

**A — Windows Defender creates VSS snapshots before quarantine.**  
When Defender detects malware, it takes a Volume Shadow Copy (VSS snapshot) of the file before deleting it. This is by design — it is Defender's "backup before delete" behavior.

**B — Batch Oplocks let a process intercept file access.**  
A process can request a batch oplock on a file, which causes it to receive a notification (and pause all other access) whenever another process tries to open that file.

**C — Cloud Files API creates dehydrated placeholders.**  
The OneDrive sync engine API can mark a file as a "cloud placeholder" — it looks like a real file but has no local data. When something tries to read it, the sync engine is supposed to hydrate it.

**D — Directory junctions redirect filesystem paths.**  
A junction point is like a symlink for directories — anything accessing `dir\file.exe` through the junction actually accesses a completely different path.

The exploit chains these to write arbitrary content to `C:\Windows\System32\TieringEngineService.exe`.

---

## 2. Step-by-Step Breakdown

**Step 1 — Set up the trap.**  
Creates a named pipe `\\.\pipe\REDSUN` and a working directory in `%TEMP%\RS-{random GUID}\`. Launches a background thread watching for new VSS snapshots.

**Step 2 — Write EICAR and trigger Defender.**  
Writes the EICAR antivirus test string (stored reversed in the binary to avoid self-detection) to `%TEMP%\RS-{GUID}\TieringEngineService.exe`, then immediately opens that file with `FILE_EXECUTE` access to trigger Defender's real-time scanner.

**Step 3 — Defender takes the bait.**  
Defender detects the EICAR signature, creates a VSS snapshot of the volume (its standard pre-quarantine backup behavior), and tries to open the file to quarantine it.

**Step 4 — Background thread spots the new VSS.**  
The thread was watching `\Device\` in the object manager for new `HarddiskVolumeShadowCopy*` devices. It finds the one Defender just created, opens `TieringEngineService.exe` from inside the shadow copy using its NT path (`\Device\HarddiskVolumeShadowCopy{N}\...`), and places a **batch oplock** on it. This freezes Defender's access to that copy.

**Step 5 — Main thread races.**  
While Defender is frozen by the oplock:
- Marks the original file for deletion using `NtSetInformationFile` with `FileDispositionInformationEx`
- Creates a Cloud Files placeholder (via `CfCreatePlaceholders`) with the same filename — a zero-byte stub that *looks* like a file

**Step 6 — Release the oplock, signal, pivot.**  
The oplock is released. The background thread signals the main thread and exits. The main thread renames the temp directory to a `.TMP` name, recreates the directory at the original path, and opens the placeholder file with another batch oplock.

**Step 7 — Create the junction.**  
While holding the oplock on the placeholder, uses `FSCTL_SET_REPARSE_POINT` to convert the working directory itself into a mount point (junction) pointing to `\??\C:\Windows\System32`. The temp directory is now transparently redirected to System32.

**Step 8 — Write to System32.**  
Loops up to 1000 times attempting `NtCreateFile` on `\??\C:\Windows\System32\TieringEngineService.exe` with `FILE_SUPERSEDE`. Because the junction is now in place, this succeeds with write access to a protected System32 binary.

**Step 9 — Execute as SYSTEM.**  
Copies itself to `System32\TieringEngineService.exe`, then instantiates the COM object `{50d185b9-fff3-4656-92c7-e4018da4361d}` (Storage Tiers Management Engine), which executes `TieringEngineService.exe` under SYSTEM context.

**Bonus — SYSTEM detection evasion.**  
`IsRunningAsLocalSystem()` runs at global scope. If the exploit detects it is already running as SYSTEM (on its second execution as the service), it opens `\\.\pipe\REDSUN`, reads the logged-in user's session ID, clones its token into that session, spawns `conhost.exe` as the user, and exits silently.

---

## 3. Detection Opportunities

| # | Indicator | Why It's Detectable |
|---|-----------|-------------------|
| 1 | Named pipe `\pipe\REDSUN` created | Hardcoded name, no legitimate software uses it |
| 2 | `CfRegisterSyncRoot` with provider `SERIOUSLYMSFT` | Hardcoded fake OneDrive provider name |
| 3 | Cloud Files placeholder created in `%TEMP%` | Placeholders never legitimately appear in Temp |
| 4 | `FSCTL_SET_REPARSE_POINT` on `%TEMP%` subdirectory → System32 | Junction from Temp to System32 is anomalous |
| 5 | `TieringEngineService.exe` written to System32 by non-Update process | Should only be touched by Windows Update |
| 6 | Batch oplock request from non-AV process | Legitimate uses are narrow and rare |
| 7 | COM CLSID `{50d185b9-...}` invoked outside svchost | Should only be started by the SCM |
| 8 | SYSTEM process spawning `conhost.exe` in user session | SYSTEM processes don't normally do this |
| 9 | VSS snapshot created within seconds of EICAR write in Temp | Defender race trigger pattern |

---

## 4. Key Hardcoded Indicators (IOCs)

```
Named pipe:     \\.\pipe\REDSUN
Provider name:  SERIOUSLYMSFT
Target file:    C:\Windows\System32\TieringEngineService.exe
COM CLSID:      {50d185b9-fff3-4656-92c7-e4018da4361d}
Temp prefix:    %TEMP%\RS-{GUID}\
Temp suffix:    .TMP / .TEMP2 (renamed working dirs)
```
