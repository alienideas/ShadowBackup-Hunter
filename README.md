# ShadowBackup-Hunter

**First-line ransomware early detection utilities** focused on **Shadow-Copy and Backup Hunting** (MITRE ATT&CK T1490 – Inhibit System Recovery).

Ransomware operators almost always try to destroy recovery options (Volume Shadow Copies, snapshots, backup catalogs) **before** encryption begins. Catching this activity gives defenders hours or even days of warning.

This repository contains two lightweight, standalone hunters:

| Platform | Script | Language |
|----------|--------|----------|
| Windows 10 / 11 / Server 2016+ | `ShadowBackup-Hunter.ps1` | PowerShell |
| Linux (most distributions) | `shadow-backup-hunter.sh` | Bash |

---

## What These Scripts Detect

### Windows (`ShadowBackup-Hunter.ps1`)
- `vssadmin delete shadows` / `resize shadowstorage`
- `wmic shadowcopy delete`
- PowerShell / WMI / CIM deletion of `Win32_ShadowCopy`
- `wbadmin delete catalog`
- `bcdedit` recovery disablement
- `diskshadow`, `ntdsutil`, `reagentc /disable`
- Stopped critical backup / VSS services
- Absence of shadow copies + recent VSS-related errors

### Linux (`shadow-backup-hunter.sh`)
- Suspicious commands: `lvremove`, `btrfs subvolume delete`, `zfs destroy`, Timeshift / Borg / Restic deletion patterns
- Missing or extremely low number of LVM / Btrfs / ZFS snapshots
- Stopped common backup services
- High file activity in typical backup directories

Both scripts produce **High-confidence** and **Medium-confidence** findings and exit with code `1` on high-confidence hits (suitable for monitoring / alerting).

---

## Requirements

### Windows
- Windows 10, Windows 11, or Windows Server 2016 and later
- PowerShell 5.1+ (built-in)
- Administrator privileges (recommended) or sufficient rights to read Security / Sysmon logs
- **Strongly recommended**: Sysmon installed (for richer process creation data) **or** process creation auditing enabled (Event ID 4688)

### Linux
- Bash 4+
- Root privileges (or capabilities to read audit logs / process list)
- Optional but highly recommended: `auditd` with `execve` rules for the tools listed in the script

---

## Quick Start

### Windows

```powershell
# Download / copy the script
# Run once (looks back 60 minutes by default)
.\ShadowBackup-Hunter.ps1

# Only show high-confidence alerts
.\ShadowBackup-Hunter.ps1 -AlertOnly

# Custom lookback window (minutes)
.\ShadowBackup-Hunter.ps1 -LookbackMinutes 30
```

Log file is written to `%TEMP%\ShadowBackup-Hunter.log` by default.

### Linux

```bash
chmod +x shadow-backup-hunter.sh

# Run once (default 60-minute lookback)
sudo ./shadow-backup-hunter.sh

# Custom lookback (minutes)
sudo ./shadow-backup-hunter.sh 15
```

Log file defaults to `/var/log/shadow-backup-hunter.log`.

---

## Scheduling (Recommended)

### Windows – Task Scheduler
1. Create a new Basic Task.
2. Trigger: Every 5–15 minutes.
3. Action: Start a program → `powershell.exe`
4. Arguments:
   ```
   -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\ShadowBackup-Hunter.ps1" -AlertOnly
   ```
5. Run whether user is logged on or not, with highest privileges (SYSTEM recommended).

### Linux – Cron
```bash
# Edit root crontab
sudo crontab -e

# Example: every 10 minutes, 15-minute lookback
*/10 * * * * /usr/local/bin/shadow-backup-hunter.sh 15 >> /var/log/shadow-backup-hunter.log 2>&1
```

Alternatively use a systemd timer for more control.

---

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | No high-confidence activity found |
| `1` | High-confidence recovery-inhibition activity detected |

Use these codes in monitoring systems, SIEM forwarders, or SOAR playbooks to trigger isolation, tickets, or notifications.

---

## Integration Ideas

- Pipe high-confidence output into your SIEM (Splunk, Elastic, Microsoft Sentinel, etc.).
- On exit code `1`, automatically isolate the host via EDR API or network ACL.
- Combine with canary / honeypot files and network exfiltration detection for a complete early-warning stack.
- Feed findings into an existing SOAR playbook that also checks for credential dumping and lateral movement.

---

## False Positives & Tuning

Legitimate backup software, storage administrators, and some patching tools may delete or resize shadow copies / snapshots.

**Recommended practices:**
- Maintain an allow-list of known backup accounts / service accounts.
- Correlate with parent process, user context, and time of day.
- Prefer running the scripts on a schedule and reviewing only the high-confidence hits first.
- On Windows, Sysmon provides cleaner parent-process lineage than native Event ID 4688.

---

## Limitations

- These are **lightweight hunters**, not full EDR replacements.
- They rely on process creation logs (Windows) and process list / audit logs (Linux).
- BYOVD (Bring Your Own Vulnerable Driver) and fully fileless techniques may evade pure process monitoring.
- Always combine with behavioral EDR, network monitoring, and immutable off-host backups.

---

## File Overview

```
.
├── README.md                     # This file
├── ShadowBackup-Hunter.ps1       # Windows PowerShell hunter
└── shadow-backup-hunter.sh       # Linux Bash hunter
```

---

## Disclaimer

These scripts are provided for defensive security purposes only.  
Test thoroughly in a non-production environment before deploying widely.  
The authors accept no liability for any damage or data loss resulting from their use.

---

**Stay ahead of ransomware — detect the recovery kill before encryption starts.**
