# ==================================================
# 99_Run_All.ps1
# JARVIS Attack Chain - Full Automated Execution
# ==================================================

param(
    [switch]$SkipConfirmation
)

$ErrorActionPreference = "Continue"

Write-Host @"
╔════════════════════════════════════════════════════════════╗
║           JARVIS ATTACK CHAIN - AUTO EXECUTION             ║
║           Full Phase Automated Execution Script            ║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

if (-not $SkipConfirmation) {
    Write-Host "`nWARNING: This script will execute all Phases sequentially." -ForegroundColor Yellow
    Write-Host "Do you want to continue? (Y/N): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host

    if ($response -ne 'Y' -and $response -ne 'y') {
        Write-Host "Execution cancelled" -ForegroundColor Red
        exit
    }
}

# Script path
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Phase list
$phases = @(
    @{Name="00_Initialize.ps1"; Title="Initialization"},
    @{Name="Phase0_Environment_Check.ps1"; Title="Environment Validation"},
    @{Name="Phase1_Reconnaissance.ps1"; Title="Reconnaissance"},
    @{Name="Phase2_Information_Gathering.ps1"; Title="Information Gathering"},
    @{Name="Phase3_AD_Compromise.ps1"; Title="AD Compromise"},
    @{Name="Phase4_Azure_Credential_Discovery.ps1"; Title="Azure Credential Discovery"},
    @{Name="Phase5_Storage_Breach.ps1"; Title="Storage Breach"},
    @{Name="Phase6_SQL_Breach.ps1"; Title="SQL Breach"},
    @{Name="Phase7_Data_Exfiltration.ps1"; Title="Data Exfiltration"},
    @{Name="Phase8_Cleanup.ps1"; Title="Cleanup"}
)

$successCount = 0
$failCount = 0

foreach ($phase in $phases) {
    $phaseFile = Join-Path $scriptPath $phase.Name
    
    Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ Executing: $($phase.Title)" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    if (Test-Path $phaseFile) {
        try {
            & $phaseFile
            
            if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
                $successCount++
                Write-Host "`n✓ $($phase.Title) succeeded" -ForegroundColor Green
            } else {
                $failCount++
                Write-Host "`n✗ $($phase.Title) failed (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
            }

        } catch {
            $failCount++
            Write-Host "`n✗ $($phase.Title) error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        $failCount++
        Write-Host "`n✗ File not found: $phaseFile" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 2
}

# Final summary
Write-Host "`n`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║           Full Execution Complete                          ║
╟────────────────────────────────────────────────────────────╢
║ Succeeded: $successCount / $($phases.Count)
║ Failed: $failCount / $($phases.Count)
║
║ Log location: $global:logPath
║
║ Next steps:
║   1. Review log files
║   2. Check Windows Defender status
║   3. Rotate credentials
║   4. Check Azure audit logs
║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $(if($failCount -eq 0){"Green"}else{"Yellow"})

Write-Host "`n[*] Full Attack Chain execution complete" -ForegroundColor Green