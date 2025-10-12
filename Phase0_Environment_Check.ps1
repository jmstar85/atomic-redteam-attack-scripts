# ==================================================
# Phase0_Environment_Check.ps1
# Environment Verification
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Execute 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 0] ENVIRONMENT VERIFICATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

Write-Host "[*] Checking current environment..." -ForegroundColor Cyan
Write-Host "  Computer: $global:currentHost" -ForegroundColor Gray
Write-Host "  User: $global:currentUser" -ForegroundColor Gray
Write-Host "  Administrator Privileges: $(if($global:isAdmin){'✓'}else{'✗'})" -ForegroundColor $(if($global:isAdmin){'Green'}else{'Red'})

if (-not $global:isAdmin) {
    Write-Host "`n✗ Administrator privileges required" -ForegroundColor Red
    exit
}

# Check Atomic Red Team
Write-Host "`n[*] Checking Atomic Red Team..." -ForegroundColor Cyan
try {
    Get-Command Invoke-AtomicTest -ErrorAction Stop | Out-Null
    Write-Host "  ✓ Atomic Red Team installed" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Atomic Red Team not installed" -ForegroundColor Red
    Write-Host "`n  [*] Installing Atomic Red Team automatically..." -ForegroundColor Yellow

    try {
        # Set TLS 1.2 for secure downloads
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Install Atomic Red Team module
        Write-Host "    [1/3] Installing invoke-atomicredteam module..." -ForegroundColor Gray
        Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force -ErrorAction Stop

        # Import the module
        Write-Host "    [2/3] Importing module..." -ForegroundColor Gray
        Import-Module invoke-atomicredteam -Force -ErrorAction Stop

        # Install Atomics folder
        Write-Host "    [3/3] Installing Atomics folder (this may take a few minutes)..." -ForegroundColor Gray
        IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
        Install-AtomicRedTeam -getAtomics -Force -ErrorAction Stop

        Write-Host "`n  ✓ Atomic Red Team installation completed successfully" -ForegroundColor Green
        Write-Host "    Installation path: C:\AtomicRedTeam" -ForegroundColor Gray

    } catch {
        Write-Host "`n  ✗ Atomic Red Team installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`n  [Manual Installation]" -ForegroundColor Yellow
        Write-Host "    1. Run PowerShell as Administrator" -ForegroundColor Gray
        Write-Host "    2. Execute: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)" -ForegroundColor Gray
        Write-Host "    3. Execute: Install-AtomicRedTeam -getAtomics" -ForegroundColor Gray
        Write-Host "`n  ⚠ Proceeding without Atomic Red Team (some tests will be skipped)" -ForegroundColor Yellow
    }
}

Write-Host "`n[PHASE 0] Completed - Proceed to Phase 1" -ForegroundColor Green

# Save result
@{
    Phase = "Phase0"
    Status = "Completed"
    Timestamp = Get-Date
    CurrentHost = $global:currentHost
    IsAdmin = $global:isAdmin
} | ConvertTo-Json | Out-File "$global:logPath\phase0_result.json"
