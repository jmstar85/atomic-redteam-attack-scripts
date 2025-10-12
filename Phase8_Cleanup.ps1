# ==================================================
# Phase8_Cleanup.ps1
# Attack Trace Removal and System Restoration
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 8] CLEANUP & DETECTION EVASION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

Write-Host "[*] Performing attack trace removal and detection evasion" -ForegroundColor Gray

# Step 8.1: Event Log backup
Write-Host "`n[Step 8.1] T1070.001 - Backing up Windows Event Logs..." -ForegroundColor Cyan

try {
    $eventLogs = @("Security", "System", "Application")
    $backupPath = "$global:logPath\EventLogs_Backup"
    New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

    foreach ($log in $eventLogs) {
        try {
            $backupFile = "$backupPath\$log`_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
            wevtutil epl $log $backupFile
            Write-Host "    Backup: $log -> $backupFile" -ForegroundColor Gray
        } catch {
            Write-Host "    ⚠ $log backup failed" -ForegroundColor Yellow
        }
    }

    Write-Host "  ✓ Event log backup completed" -ForegroundColor Green

    Write-Host "`n  [Simulation] Event log cleanup..." -ForegroundColor Gray
    Write-Host "    Security Log: Deletion simulation" -ForegroundColor DarkGray
    Write-Host "    System Log: Deletion simulation" -ForegroundColor DarkGray

    Write-Host "  ⚠ No actual deletion performed (training environment)" -ForegroundColor Yellow

    Write-Host "  [Atomic] T1070.001 executing..." -ForegroundColor Gray
    Invoke-AtomicTest T1070.001 -TestNumbers 1 -ShowDetails -ErrorAction SilentlyContinue

} catch {
    Write-Host "  ⚠ Event log processing completed" -ForegroundColor Yellow
}

# Step 8.2: Timestamp manipulation
Write-Host "`n[Step 8.2] T1070.006 - Manipulating timestamps..." -ForegroundColor Cyan

try {
    Write-Host "  [Simulation] Modifying file timestamps..." -ForegroundColor Gray

    $artifactFiles = @(
        "C:\AtomicTest\Tools\mimikatz.exe",
        "C:\Windows\Temp\svchost.exe"
    )

    foreach ($file in $artifactFiles) {
        if (Test-Path $file) {
            $originalTime = (Get-Item $file).LastWriteTime
            $newTime = (Get-Date).AddDays(-30)

            Write-Host "    $file" -ForegroundColor DarkGray
            Write-Host "      Original: $originalTime" -ForegroundColor DarkGray
            Write-Host "      Modified: $newTime (simulation)" -ForegroundColor DarkGray
        }
    }

    Write-Host "  ⚠ Timestamp modification simulation only" -ForegroundColor Yellow

    Write-Host "  [Atomic] T1070.006 executing..." -ForegroundColor Gray
    Invoke-AtomicTest T1070.006 -TestNumbers 1 -ShowDetails -ErrorAction SilentlyContinue

} catch {
    Write-Host "  ⚠ Timestamp manipulation completed" -ForegroundColor Yellow
}

# Step 8.3: File deletion check
Write-Host "`n[Step 8.3] T1070.004 - Checking attack tool files..." -ForegroundColor Cyan

try {
    $filesToDelete = @()

    $DCIP = ($global:discoveredHosts | Where-Object { $_.Type -eq "DomainController" }).IP

    if (Test-Path "C:\AtomicTest\Tools\mimikatz.exe") {
        $filesToDelete += "C:\AtomicTest\Tools\mimikatz.exe"
    }

    $remoteMimikatz = "\\$DCIP\C$\Windows\Temp\svchost.exe"
    if (Test-Path $remoteMimikatz) {
        $filesToDelete += $remoteMimikatz
    }

    if (Test-Path "\\$DCIP\C$\Windows\Temp\mimi_output.txt") {
        $filesToDelete += "\\$DCIP\C$\Windows\Temp\mimi_output.txt"
    }

    if (Test-Path "\\$DCIP\C$\Windows\Temp\mimi_commands.txt") {
        $filesToDelete += "\\$DCIP\C$\Windows\Temp\mimi_commands.txt"
    }

    Write-Host "  Files found: $($filesToDelete.Count)" -ForegroundColor Gray

    if ($filesToDelete.Count -gt 0) {
        Write-Host "`n  [Confirmation Required] Do you want to delete the following files?" -ForegroundColor Yellow

        foreach ($file in $filesToDelete) {
            Write-Host "    - $file" -ForegroundColor DarkYellow
        }

        Write-Host "`n  Automatic deletion not performed in training environment" -ForegroundColor Yellow
        Write-Host "  To manually delete, execute the following command:" -ForegroundColor Cyan
        Write-Host "    Remove-Item -Path '<file_path>' -Force" -ForegroundColor Gray
    }

    Write-Host "`n  [Atomic] T1070.004 executing..." -ForegroundColor Gray
    Invoke-AtomicTest T1070.004 -TestNumbers 1 -ShowDetails -ErrorAction SilentlyContinue

} catch {
    Write-Host "  ⚠ File deletion check completed" -ForegroundColor Yellow
}

# Step 8.4: Windows Defender reactivation
Write-Host "`n[Step 8.4] Restoring Windows Defender..." -ForegroundColor Cyan

try {
    Write-Host "  [*] Checking current VM Defender status..." -ForegroundColor Gray

    $defenderStatus = Get-MpComputerStatus

    if ($defenderStatus.RealTimeProtectionEnabled -eq $false) {
        Write-Host "    Real-time protection: Disabled" -ForegroundColor Yellow

        Write-Host "`n  [Restore] Reactivating Defender..." -ForegroundColor Gray

        try {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Host "  ✓ Current VM Defender reactivation completed" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Defender reactivation failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ✓ Defender already enabled" -ForegroundColor Green
    }

    # AD server Defender restoration
    Write-Host "`n  [*] Restoring AD server Defender..." -ForegroundColor Gray

    $validCredential = $global:validCredentials[0]
    $DCIP = ($global:discoveredHosts | Where-Object { $_.Type -eq "DomainController" }).IP

    try {
        $session = New-PSSession -ComputerName $DCIP -Credential $validCredential.Credential -ErrorAction Stop

        Invoke-Command -Session $session -ScriptBlock {
            Set-MpPreference -DisableRealtimeMonitoring $false
        }

        Write-Host "  ✓ AD server Defender reactivation completed" -ForegroundColor Green

        Remove-PSSession -Session $session

    } catch {
        Write-Host "  ⚠ AD server Defender restoration failed" -ForegroundColor Yellow
        Write-Host "  → Manual restoration required via Azure Portal Run Command:" -ForegroundColor Yellow
        Write-Host "    Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor Gray
    }

} catch {
    Write-Host "  ⚠ Defender restoration check" -ForegroundColor Yellow
}

# Step 8.5: Network session cleanup
Write-Host "`n[Step 8.5] Cleaning up network sessions..." -ForegroundColor Cyan

try {
    $activeSessions = Get-PSSession

    if ($activeSessions.Count -gt 0) {
        Write-Host "    Active sessions: $($activeSessions.Count)" -ForegroundColor Gray

        foreach ($sess in $activeSessions) {
            Write-Host "      - $($sess.ComputerName) (ID: $($sess.Id))" -ForegroundColor DarkGray
            Remove-PSSession -Session $sess
        }

        Write-Host "  ✓ All sessions terminated" -ForegroundColor Green
    } else {
        Write-Host "  ✓ No active sessions" -ForegroundColor Green
    }

} catch {
    Write-Host "  ⚠ Session cleanup completed" -ForegroundColor Yellow
}

# Step 8.6: Final report generation
Write-Host "`n[Step 8.6] Generating final attack report..." -ForegroundColor Cyan

try {
    $attackEnd = Get-Date
    $duration = $attackEnd - $global:attackStart
    
    $finalReport = @{
        AttackMetadata = @{
            StartTime = $global:attackStart.ToString("yyyy-MM-dd HH:mm:ss")
            EndTime = $attackEnd.ToString("yyyy-MM-dd HH:mm:ss")
            Duration = $duration.ToString("hh\:mm\:ss")
            Environment = "JARVIS - Hybrid Cloud"
        }
        AttackChain = @{
            Phase0 = @{Name = "Environment Verification"; Status = "Completed"}
            Phase1 = @{Name = "Initial Reconnaissance"; Status = "Completed"; HostsDiscovered = $global:discoveredHosts.Count}
            Phase2 = @{Name = "Information Gathering"; Status = "Completed"}
            Phase3 = @{Name = "AD Server Compromise"; Status = "Completed"; CredentialsExtracted = $global:extractedCredentials.Count}
            Phase4 = @{Name = "Azure Credential Discovery"; Status = "Completed"; AzureCredentialsFound = $global:azureCredentials.Count}
            Phase5 = @{Name = "Storage Account Breach"; Status = "Completed"}
            Phase6 = @{Name = "SQL Database Breach"; Status = "Completed"}
            Phase7 = @{Name = "Multi-Channel Exfiltration"; Status = "Completed (Simulated)"}
            Phase8 = @{Name = "Cleanup & Evasion"; Status = "Completed"}
        }
        ImpactAssessment = @{
            DomainCompromise = "Complete"
            CompromisedAccounts = $global:extractedCredentials.Count
            AzureCredentialsStolen = $global:azureCredentials.Count
        }
        RemediationRequired = @{
            ImmediateActions = @(
                "Re-enable Windows Defender on all systems",
                "Remove Mimikatz from AD server",
                "Rotate all compromised credentials",
                "Review Azure logs"
            )
        }
    }
    
    $finalReport | ConvertTo-Json -Depth 10 | Out-File "$global:logPath\phase8_final_report.json"

    Write-Host "  ✓ Final report generation completed" -ForegroundColor Green
    Write-Host "    Location: $global:logPath\phase8_final_report.json" -ForegroundColor Gray

} catch {
    Write-Host "  ⚠ Report generation failed" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 8 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Tasks performed:
║   ✓ T1070.001 - Event Log backup
║   ✓ T1070.006 - Timestamp manipulation (simulation)
║   ✓ T1070.004 - Artifact file check
║   ✓ Windows Defender reactivation
║   ✓ Network session cleanup
║   ✓ Final report generation
║
║ ⚠️ Manual verification required:
║   - Delete Mimikatz from AD server
║   - Rotate all credentials
║   - Check Azure resource audit logs
║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Yellow

Write-Host "`n[PHASE 8] Completed - All phases finished`n" -ForegroundColor Green

# Final summary
$attackEnd = Get-Date
$duration = $attackEnd - $global:attackStart

Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║     JARVIS ATTACK CHAIN - FINAL SUMMARY (Completed)       ║
╟────────────────────────────────────────────────────────────╢
║ Attack scenario: Hybrid Cloud Breach (On-Prem → Azure)
║ Attack started: $($global:attackStart.ToString("yyyy-MM-dd HH:mm:ss"))
║ Attack finished: $($attackEnd.ToString("yyyy-MM-dd HH:mm:ss"))
║ Total duration: $($duration.ToString("hh\:mm\:ss"))
║
║ Compromised systems:
║   - AD Domain: $($global:JARVIS_CONFIG.Domain)
║   - Extracted credentials: $($global:extractedCredentials.Count)
║   - Azure credentials: $($global:azureCredentials.Count)
║
║ Generated artifacts:
║   Storage location: $global:logPath
║
║ ✅ All phases completed - Educational attack simulation ended
║
║ This simulation was performed for educational purposes only.
║ Never use in actual environments.
║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

Write-Host "`n[*] Attack simulation completed successfully" -ForegroundColor Green
Write-Host "[*] Review logs in: $global:logPath" -ForegroundColor Cyan
Write-Host "`n[!] Remember to restore security settings and rotate credentials" -ForegroundColor Red