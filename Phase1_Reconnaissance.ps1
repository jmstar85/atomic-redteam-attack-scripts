# ==================================================
# Phase1_Reconnaissance.ps1
# Initial Reconnaissance
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 1] INITIAL ACCESS & RECONNAISSANCE" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

$DCIP = $global:JARVIS_CONFIG.TargetDC_IP
$VMIP = $global:JARVIS_CONFIG.TargetVM_IP
$DCName = $global:JARVIS_CONFIG.TargetDC_Name
$VMName = $global:JARVIS_CONFIG.TargetVM_Name
$Domain = $global:JARVIS_CONFIG.Domain

$phase1Results = @{
    HostDiscovery = $false
    PortScanning = $false
    AccountEnum = $false
}

# Step 1.1: T1046 - Network Service Discovery
Write-Host "`n[Step 1.1] T1046 - Network Service Discovery..." -ForegroundColor Cyan

$targets = @(
    @{Name=$DCName; IP=$DCIP; Type="DomainController"},
    @{Name=$VMName; IP=$VMIP; Type="Workstation"}
)

foreach ($target in $targets) {
    Write-Host "`n  [Scan] $($target.Name) ($($target.IP))" -ForegroundColor Gray

    $pingResult = Test-Connection -ComputerName $target.IP -Count 1 -Quiet

    if ($pingResult) {
        Write-Host "    ✓ Host active" -ForegroundColor Green
        
        $commonPorts = @(
            @{Port=445; Service="SMB"},
            @{Port=3389; Service="RDP"},
            @{Port=135; Service="RPC"},
            @{Port=88; Service="Kerberos"},
            @{Port=389; Service="LDAP"}
        )
        
        $openPorts = @()
        
        foreach ($portInfo in $commonPorts) {
            $portTest = Test-NetConnection -ComputerName $target.IP -Port $portInfo.Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            
            if ($portTest.TcpTestSucceeded) {
                Write-Host "    ✓ Port $($portInfo.Port) ($($portInfo.Service)) Open" -ForegroundColor Green
                $openPorts += $portInfo
            }
        }
        
        $global:discoveredHosts += @{
            Name = $target.Name
            IP = $target.IP
            Type = $target.Type
            OpenPorts = $openPorts
            Reachable = $true
        }
        
        $phase1Results.HostDiscovery = $true
        $phase1Results.PortScanning = $true
        
    } else {
        Write-Host "    ✗ Host - No response" -ForegroundColor Red
        
        $global:discoveredHosts += @{
            Name = $target.Name
            IP = $target.IP
            Type = $target.Type
            Reachable = $false
        }
    }
}

# Step 1.2: T1087.002 - Domain Account Discovery
Write-Host "`n[Step 1.2] T1087.002 - Domain Account Discovery..." -ForegroundColor Cyan

$domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole

if ($domainRole -ge 1) {
    Write-Host "  [*] Domain environment detected: $Domain" -ForegroundColor Yellow

    try {
        $domainUsers = net user /domain 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Domain user list obtained" -ForegroundColor Green
            
            $userLines = $domainUsers -split "`n" | Where-Object { $_ -match "^\s*\w+" -and $_ -notmatch "The command|User accounts" }
            
            foreach ($line in $userLines) {
                $users = $line -split "\s+" | Where-Object { $_ }
                $global:discoveredAccounts += $users
            }
            
            Write-Host "    Discovered accounts: $($global:discoveredAccounts.Count)" -ForegroundColor Gray

            $phase1Results.AccountEnum = $true
        }
    } catch {
        Write-Host "  ⚠ Domain account enumeration failed (Authentication required)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [*] Standalone environment - Local accounts only" -ForegroundColor Yellow
}

# Save results
$phase1Data = @{
    DiscoveredHosts = $global:discoveredHosts
    DiscoveredAccounts = $global:discoveredAccounts
    Timestamp = Get-Date
}

$phase1Data | ConvertTo-Json -Depth 5 | Out-File "$global:logPath\phase1_reconnaissance.json"

# Summary
$successCount = ($phase1Results.Values | Where-Object { $_ -eq $true }).Count

Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 1 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Success rate: $successCount / 3
║
║ Discovered hosts: $(($global:discoveredHosts | Where-Object {$_.Reachable}).Count)
║   - $DCName (DC): $(if(($global:discoveredHosts | Where-Object {$_.Name -eq $DCName}).Reachable){'✓'}else{'✗'})
║   - $VMName (WS): $(if(($global:discoveredHosts | Where-Object {$_.Name -eq $VMName}).Reachable){'✓'}else{'✗'})
║
║ Discovered accounts: $($global:discoveredAccounts.Count)
║
║ Next step: Phase 2 (Information Gathering)
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $(if($successCount -eq 3){"Green"}else{"Yellow"})

Write-Host "`n[PHASE 1] Completed - Proceed to Phase 2`n" -ForegroundColor Green