#!/usr/bin/env bash
# shadow-backup-hunter.sh
# First-line ransomware early detection: Snapshot / Backup hunting on Linux
# Compatible with most modern distros (Ubuntu, RHEL, Debian, SUSE…)
# Run as root or via cron / systemd timer

set -euo pipefail

LOOKBACK_MINUTES=${1:-60}
LOG_FILE="${LOG_FILE:-/var/log/shadow-backup-hunter.log}"
ALERT=0

log() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

log INFO "=== shadow-backup-hunter started (lookback ${LOOKBACK_MINUTES}m) ==="

# -------------------------------------------------
# 1. Suspicious process / command detections
# -------------------------------------------------
SUSPICIOUS_CMDS=(
    "lvremove" "lvcreate.*--snapshot" "lvconvert"
    "btrfs.*subvolume.*delete" "btrfs.*subvolume.*delete"
    "zfs.*destroy" "zfs.*destroy"
    "timeshift.*--delete" "timeshift.*delete"
    "rsnapshot.*delete" "borg.*delete" "restic.*forget.*--prune"
    "rm -rf.*/(backup|snapshot|restic|borg|timeshift)"
)

# Check recent process history (ps + auditd if available)
if command -v ausearch &>/dev/null; then
    for cmd in "${SUSPICIOUS_CMDS[@]}"; do
        hits=$(ausearch -ts recent -i -k execve 2>/dev/null | grep -E "$cmd" | tail -n 20 || true)
        if [[ -n "$hits" ]]; then
            log CRITICAL "Suspicious command pattern matched: $cmd"
            echo "$hits" | while read -r line; do log CRITICAL "  $line"; done
            ALERT=1
        fi
    done
fi

# Fallback: check current process list + recent bash history of root
ps auxww | grep -E "$(IFS='|'; echo "${SUSPICIOUS_CMDS[*]}")" | grep -v grep | while read -r line; do
    log CRITICAL "Running suspicious process: $line"
    ALERT=1
done

# -------------------------------------------------
# 2. Snapshot health checks
# -------------------------------------------------
# LVM snapshots
if command -v lvs &>/dev/null; then
    snap_count=$(lvs --noheadings -o lv_attr 2>/dev/null | grep -c '^....s' || true)
    if [[ $snap_count -eq 0 ]]; then
        log WARN "No LVM snapshots currently present"
    fi
fi

# Btrfs subvolumes / snapshots
if command -v btrfs &>/dev/null; then
    for mount in $(findmnt -t btrfs -n -o TARGET 2>/dev/null); do
        subvol_count=$(btrfs subvolume list "$mount" 2>/dev/null | wc -l || true)
        if [[ $subvol_count -lt 2 ]]; then
            log WARN "Very few Btrfs subvolumes on $mount (count=$subvol_count)"
        fi
    done
fi

# ZFS snapshots
if command -v zfs &>/dev/null; then
    zfs_snap_count=$(zfs list -t snapshot 2>/dev/null | wc -l || true)
    if [[ $zfs_snap_count -le 1 ]]; then
        log WARN "Almost no ZFS snapshots present"
    fi
fi

# -------------------------------------------------
# 3. Common backup service / tool status
# -------------------------------------------------
BACKUP_SERVICES=(
    "borgbackup" "restic" "rsnapshot" "timeshift"
    "veeam" "acronis" "bacula-fd" "bareos-fd"
    "duplicati" "urbackupclient"
)

for svc in "${BACKUP_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "$svc"; then
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        if [[ "$status" != "active" && "$status" != "unknown" ]]; then
            log WARN "Backup-related service $svc is $status"
        fi
    fi
done

# -------------------------------------------------
# 4. Recent deletions in common backup locations
# -------------------------------------------------
BACKUP_PATHS=(
    "/var/backups" "/backup" "/mnt/backup" "/opt/backup"
    "/.snapshots" "/timeshift" "/var/lib/timeshift"
    "/root/.cache/borg" "/root/.cache/restic"
)

for path in "${BACKUP_PATHS[@]}"; do
    if [[ -d "$path" ]]; then
        # Files deleted in the last LOOKBACK_MINUTES
        deleted=$(find "$path" -type f -amin -"$LOOKBACK_MINUTES" -delete 2>/dev/null | wc -l || true)
        # Note: the above is just a probe; in real use you would use auditd or inotify
        recent_mods=$(find "$path" -type f -mmin -"$LOOKBACK_MINUTES" 2>/dev/null | wc -l || true)
        if [[ $recent_mods -gt 50 ]]; then
            log WARN "High file activity ($recent_mods files) under $path in last ${LOOKBACK_MINUTES}m"
        fi
    fi
done

# -------------------------------------------------
# Final status
# -------------------------------------------------
if [[ $ALERT -eq 1 ]]; then
    log CRITICAL "HIGH CONFIDENCE: Possible ransomware recovery-inhibition activity detected!"
    # Optional: send to SIEM / Slack / pagerduty / isolate host
    exit 1
else
    log INFO "No high-confidence snapshot/backup hunting activity found."
    exit 0
fi