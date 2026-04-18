# RedSun Detection Kit

**UPDATE April 17, 2026:** Huntress Labs is now observing active exploitation of RedSun in the wild. Use these detection tools immediately.

This repository contains analysis and detection tools for the **RedSun** exploit – a Windows Defender zero‑day that abuses VSS snapshots, batch oplocks, and directory junctions to gain SYSTEM privileges.

## Detection Tools
**Sigma Rules** (`Sigma_Rules_RedSun.yml`): 7 rules to detect RedSun activity in your SIEM.
**PowerShell Detector** (`detect_redsun.ps1`): A script to check for key indicators on a live system.

## Repository Contents

- `RedSun_Analysis.md` – Full technical write‑up of the exploit chain.
- `Sigma_Rules_RedSun.yml` – YAML file with all detection rules.
- `mitigation_guide.md` – Immediate steps for Windows admins.
- `detect_redsun.ps1` – PowerShell script to scan for RedSun artifacts.

## Get the Full Kit

For a complete, ready‑to‑deploy response kit, see my gig on **(http://www.fiverr.com/s/wk0xRgB)** or **[Upwork link]** .

## Support My Work

If you find this useful, consider [buying me a coffee ☕]((https://www.buymeacoffee.com/shellcod3)) (set up later).
