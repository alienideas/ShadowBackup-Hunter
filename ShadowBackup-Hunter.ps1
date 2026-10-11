# ShadowBackup-Hunter.ps1
# First-line ransomware early detection: Shadow Copy + Backup hunting
# Run as Administrator (or via scheduled task / EDR)
# Compatible with Windows 10+ and Windows Server 2016+

[CmdletBinding()]
param(
    [int]$LookbackMinutes = 60,          # How far back to search Event Logs
    [switch]$AlertOnly,                  # Only show high-confidence hits
    [string]$LogPath = "$env:TEMP\ShadowBackup-Hunter.log"
)

$ErrorActionPreference = "SilentlyContinue"
$HighConfidence = @()
$MediumConfidence = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

Write-Log "=== ShadowBackup-Hunter started ==="

# -------------------------------------------------
# 1. High-confidence process command-line detections
# -------------------------------------------------
$suspiciousPatterns = @(
    @{ Name = "vssadmin delete shadows"; Pattern = 'vssadmin.*delete.*shadows' },
    @{ Name = "vssadmin resize shadowstorage"; Pattern = 'vssadmin.*resize.*shadowstorage' },
    @{ Name = "wmic shadowcopy delete"; Pattern = 'wmic.*shadowcopy.*delete' },
    @{ Name = "PowerShell Win32_ShadowCopy Delete"; Pattern = '(Get-WmiObject|gwmi|Get-CimInstance|gcim).*Win32_ShadowCopy.*(Delete|Remove-WmiObject|Remove-CimInstance)' },
    @{ Name = "wbadmin delete catalog"; Pattern = 'wbadmin.*delete.*(catalog|systemstatebackup)' },
    @{ Name = "bcdedit recovery disable"; Pattern = 'bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)' },
    @{ Name = "diskshadow"; Pattern = 'diskshadow' },
    @{ Name = "ntdsutil (AD shadow)"; Pattern = 'ntdsutil.*(activate\s+instance|ifm|create\s+full)' },
    @{ Name = "reagentc disable"; Pattern = 'reagentc.*/disable' }
)

# Prefer Sysmon Event ID 1 if present, otherwise Security 4688
$events = @()
try {
    $events += Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1
        StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
    } -ErrorAction Stop
} catch {}

try {
    $events += Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4688
        StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
    } -ErrorAction Stop
} catch {}

foreach ($evt in $events) {
    $cmd = $null
    if ($evt.Id -eq 1) { $cmd = $evt.Properties[10].Value }          # Sysmon CommandLine
    if ($evt.Id -eq 4688) { $cmd = $evt.Properties[8].Value }         # Security CommandLine

    if (-not $cmd) { continue }

    foreach ($p in $suspiciousPatterns) {
        if ($cmd -match $p.Pattern) {
            $HighConfidence += [PSCustomObject]@{
                Time        = $evt.TimeCreated
                Detection   = $p.Name
                CommandLine = $cmd
                Parent      = if ($evt.Id -eq 1) { $evt.Properties[20].Value } else { "N/A" }
                User        = $evt.Properties[1].Value
            }
        }
    }
}

# -------------------------------------------------
# 2. Backup / VSS service status
# -------------------------------------------------
$criticalServices = @(
    "VSS", "swprv", "wbengine",          # Volume Shadow Copy + Windows Backup
    "VeeamBackupSvc", "VeeamBrokerSvc",  # Common backup products
    "BackupExecAgentAccelerator", "BackupExecJobEngine",
    "AcronisAgent", "ShadowProtectSvc"
)

foreach ($svcName in $criticalServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Running") {
        $MediumConfidence += "Service '$($svc.DisplayName)' ($svcName) is $($svc.Status)"
    }
}

# -------------------------------------------------
# 3. Current shadow copy status (quick health check)
# -------------------------------------------------
try {
    $shadows = vssadmin list shadows 2>&1
    if ($shadows -match "No items found that satisfy the query") {
        $MediumConfidence += "No Volume Shadow Copies currently exist on this system"
    }
} catch {}

# -------------------------------------------------
# 4. Recent VSS / backup related Event Log noise
# -------------------------------------------------
try {
    $vssEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'volsnap','VSS','Microsoft-Windows-Backup'
        StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
        Level = 2,3   # Error + Warning
    } -MaxEvents 20 -ErrorAction SilentlyContinue

    foreach ($e in $vssEvents) {
        $MediumConfidence += "Event $($e.Id) from $($e.ProviderName): $($e.Message.Substring(0,[Math]::Min(120,$e.Message.Length)))..."
    }
} catch {}

# -------------------------------------------------
# Output
# -------------------------------------------------
Write-Log "High-confidence detections: $($HighConfidence.Count)"
$HighConfidence | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }

if (-not $AlertOnly) {
    Write-Log "Medium-confidence / contextual findings:"
    $MediumConfidence | ForEach-Object { Write-Log $_ "WARN" }
}

if ($HighConfidence.Count -gt 0) {
    Write-Log "CRITICAL: Possible ransomware recovery-inhibition activity detected!" "CRITICAL"
    # Optional: trigger isolation / ticket / SIEM webhook here
    exit 1
} else {
    Write-Log "No high-confidence shadow-copy / backup hunting activity found in the last $LookbackMinutes minutes."
    exit 0
}