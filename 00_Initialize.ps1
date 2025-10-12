# ==================================================
# 00_Initialize.ps1
# JARVIS Attack Chain - Initial Setup and Global Variables
# ==================================================

param(
    [string]$TargetDC_IP = "[YOUR_DC_IP]",
    [string]$TargetVM_IP = "[YOUR_VM_IP]",
    [string]$TargetDC_Name = "[YOUR_DC_NAME]",
    [string]$TargetVM_Name = "[YOUR_VM_NAME]",
    [string]$Domain = "[YOUR_DOMAIN]",
    [string]$StorageAccount = "[YOUR_STORAGE_ACCOUNT]",
    [string]$SQLServer = "[YOUR_SQL_SERVER]"
)

# Global Configuration
$global:JARVIS_CONFIG = @{
    TargetDC_IP = $TargetDC_IP
    TargetVM_IP = $TargetVM_IP
    TargetDC_Name = $TargetDC_Name
    TargetVM_Name = $TargetVM_Name
    Domain = $Domain
    StorageAccount = $StorageAccount
    SQLServer = $SQLServer
    AttackerIP = "[YOUR_ATTACKER_IP]"
    C2Server = "[YOUR_C2_SERVER_URL]"
}

# Attack start time
$global:attackStart = Get-Date

# Log path
$global:logPath = "C:\AtomicTest\Logs\Attack_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $global:logPath -ItemType Directory -Force | Out-Null

# Global variables - Shared information between Phases
$global:discoveredHosts = @()
$global:discoveredAccounts = @()
$global:validCredentials = @()
$global:extractedCredentials = @()
$global:azureCredentials = @()
$global:storageContainers = @()
$global:sqlExfiltratedData = @()

# Lateral Movement session management
$global:vmjarvisfeSession = $null
$global:vmjarvisfeCredential = $null

# Environment information
$global:currentHost = $env:COMPUTERNAME
$global:currentUser = $env:USERNAME
$global:isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host @"
╔════════════════════════════════════════════════════════════╗
║           JARVIS ATTACK CHAIN INITIALIZATION               ║
║           Domain: $Domain                     ║
║           Target Infrastructure: JARVIS Corp              ║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

Write-Host "`n[Initialization] Global variables setup completed" -ForegroundColor Green
Write-Host "  Log Path: $global:logPath" -ForegroundColor Gray
Write-Host "  Current Host: $global:currentHost" -ForegroundColor Gray
Write-Host "  Administrator Privileges: $(if($global:isAdmin){'Yes'}else{'No'})" -ForegroundColor Gray

# Configuration validation
Write-Host "`n[Validation] Checking configuration..." -ForegroundColor Cyan
$configErrors = @()

# Check for placeholder values
$placeholders = @(
    @{Key="TargetDC_IP"; Value=$TargetDC_IP},
    @{Key="TargetVM_IP"; Value=$TargetVM_IP},
    @{Key="Domain"; Value=$Domain}
)

foreach ($item in $placeholders) {
    if ($item.Value -match "\[YOUR_.*\]") {
        $configErrors += "  ✗ $($item.Key) is not configured (placeholder detected)"
    }
}

if ($configErrors.Count -gt 0) {
    Write-Host "`n  ⚠ Configuration issues detected:" -ForegroundColor Yellow
    $configErrors | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host "`n  Please configure values by running:" -ForegroundColor Yellow
    Write-Host "    .\00_Initialize.ps1 -TargetDC_IP `"<IP>`" -TargetVM_IP `"<IP>`" -Domain `"<domain>`" ..." -ForegroundColor Gray
    Write-Host "`n  ⚠ Proceeding with placeholder values (for testing only)" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ All required configurations set" -ForegroundColor Green
}

# Save configuration
$global:JARVIS_CONFIG | ConvertTo-Json | Out-File "$global:logPath\00_config.json"

Write-Host "`nReady - Execute from Phase 0`n" -ForegroundColor Cyan