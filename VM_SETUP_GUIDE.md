# VM Pre-requisite Setup Guide

## 📋 Overview

For the attack scenario to function properly, specific accounts, services, and files must be pre-configured on **[YOUR_VM_NAME]** and **[YOUR_DC_NAME]** servers.

---

## 🖥️ 1. [YOUR_VM_NAME] (Pivot Host)

### 1.1 Required Network Configuration

| Item | Value |
|------|-------|
| **IP Address** | `[YOUR_VM_IP]` |
| **Hostname** | `[YOUR_VM_NAME]` |
| **Domain** | `[YOUR_DOMAIN]` (or Workgroup) |
| **Firewall** | Allow SMB (445), WinRM (5985), ICMP |

### 1.2 Required Account Setup

The attack scripts will attempt brute force with the following accounts:

| Username | Password | Privileges | Required |
|----------|----------|------------|----------|
| **[TEST_USER_1]** | `[TEST_PASSWORD_1]` | Local Administrator | ✅ Required |
| **[TEST_USER_2]** | `[TEST_PASSWORD_2]` | Local User | Optional |
| **Administrator** | `[TEST_PASSWORD_FALLBACK]` | Local Administrator | Fallback |

#### PowerShell Account Creation Example:

```powershell
# Create [TEST_USER_1] account (Local Administrator)
$password = ConvertTo-SecureString "[TEST_PASSWORD_1]" -AsPlainText -Force
New-LocalUser -Name "[TEST_USER_1]" -Password $password -FullName "Test User 1" -Description "Test User"
Add-LocalGroupMember -Group "Administrators" -Member "[TEST_USER_1]"

# Create [TEST_USER_2] account (Regular User)
New-LocalUser -Name "[TEST_USER_2]" -Password $password -FullName "Test User 2" -Description "Test User"
Add-LocalGroupMember -Group "Users" -Member "[TEST_USER_2]"

# Disable password expiration
Set-LocalUser -Name "[TEST_USER_1]" -PasswordNeverExpires $true
Set-LocalUser -Name "[TEST_USER_2]" -PasswordNeverExpires $true
```

### 1.3 Enable PowerShell Remoting

Enable WinRM to allow remote access from the attacker:

```powershell
# Enable WinRM
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Trust all hosts (Test environment only)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Start WinRM service
Start-Service WinRM
Set-Service WinRM -StartupType Automatic

# Verify firewall rule
Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" | Enable-NetFirewallRule
```

### 1.4 Enable SMB Sharing

Attacker must be able to access C$ administrative share:

```powershell
# Start SMB service
Start-Service LanmanServer
Set-Service LanmanServer -StartupType Automatic

# Enable administrative shares (Registry)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                 -Name "AutoShareWks" -Value 1 -Type DWord

# System restart required
Restart-Computer
```

### 1.5 Windows Defender Configuration (Optional)

To avoid detection when transferring Mimikatz in Phase 3:

```powershell
# Disable real-time protection (Test environment only)
Set-MpPreference -DisableRealtimeMonitoring $true

# Add exclusion paths
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionPath "C:\Users\[TEST_USER_1]\AppData\Local\Temp"
```

---

## 🏢 2. [YOUR_DC_NAME] (Active Directory Server)

### 2.1 Required Network Configuration

| Item | Value |
|------|-------|
| **IP Address** | `[YOUR_DC_IP]` |
| **Hostname** | `[YOUR_DC_NAME]` |
| **Domain** | `[YOUR_DOMAIN]` (DC) |
| **Firewall** | Allow SMB (445), WinRM (5985), LDAP (389), ICMP |

### 2.2 Required Domain Accounts

The attack scripts target the following domain accounts:

| Username | Password | Privileges | Purpose |
|----------|----------|------------|---------|
| **[TEST_DOMAIN_ADMIN]** | `[TEST_DOMAIN_ADMIN_PASSWORD]` | Domain Admin | ✅ Primary Target |
| **[TEST_USER_2]** | `[TEST_PASSWORD_2]` | Domain User | Azure Authentication |
| **[TEST_USER_1]** | `[TEST_PASSWORD_1]` | Domain User | Regular User |
| **Administrator** | (Common password attempts) | Domain Admin | Fallback |

#### PowerShell Domain Account Creation:

```powershell
# Import AD module
Import-Module ActiveDirectory

# Create [TEST_DOMAIN_ADMIN] account (Service Account, Domain Admin)
$password = ConvertTo-SecureString "[TEST_DOMAIN_ADMIN_PASSWORD]" -AsPlainText -Force
New-ADUser -Name "[TEST_DOMAIN_ADMIN]" `
           -SamAccountName "[TEST_DOMAIN_ADMIN]" `
           -UserPrincipalName "[TEST_DOMAIN_ADMIN]@[YOUR_DOMAIN]" `
           -AccountPassword $password `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -Description "Service Account for Azure Integration"

Add-ADGroupMember -Identity "Domain Admins" -Members "[TEST_DOMAIN_ADMIN]"

# Create [TEST_USER_2] account (Domain User)
$password2 = ConvertTo-SecureString "[TEST_PASSWORD_2]" -AsPlainText -Force
New-ADUser -Name "[TEST_USER_2]" `
           -SamAccountName "[TEST_USER_2]" `
           -UserPrincipalName "[TEST_USER_2]@[YOUR_DOMAIN]" `
           -AccountPassword $password2 `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -Description "Regular Domain User"

# Create [TEST_USER_1] account
New-ADUser -Name "[TEST_USER_1]" `
           -SamAccountName "[TEST_USER_1]" `
           -UserPrincipalName "[TEST_USER_1]@[YOUR_DOMAIN]" `
           -AccountPassword $password2 `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -Description "Regular Domain User"
```

### 2.3 Enable PowerShell Remoting & WMI

Remote access from [YOUR_VM_NAME] to AD must be enabled:

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Firewall rules
Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"

# WMI firewall rules
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"

# Enable DCOM
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "Y"
```

### 2.4 Create Mock Azure Integration Files (For Phase 4)

Create credential files that will be discovered during Phase 4 file search:

```powershell
# Create C:\Scripts directory
New-Item -Path "C:\Scripts" -ItemType Directory -Force

# Azure Storage Account configuration file
$azureConfig = @"
# Azure Storage Configuration
STORAGE_ACCOUNT=[YOUR_STORAGE_ACCOUNT]
STORAGE_KEY=[YOUR_STORAGE_ACCOUNT_KEY]
STORAGE_CONTAINER=sensitive-data
"@

$azureConfig | Out-File "C:\Scripts\azure_config.txt" -Encoding ASCII

# SQL Server connection string file
$sqlConfig = @"
# SQL Server Configuration
SQL_SERVER=[YOUR_SQL_SERVER].database.windows.net
SQL_DATABASE=[YOUR_SQL_DATABASE]
SQL_USERNAME=[YOUR_SQL_USERNAME]
SQL_PASSWORD=[YOUR_SQL_PASSWORD]
CONNECTION_STRING=Server=[YOUR_SQL_SERVER].database.windows.net;Database=[YOUR_SQL_DATABASE];User Id=[YOUR_SQL_USERNAME];Password=[YOUR_SQL_PASSWORD];
"@

$sqlConfig | Out-File "C:\Scripts\sql_config.txt" -Encoding ASCII

# Copy to Administrator's Documents folder
Copy-Item "C:\Scripts\*.txt" -Destination "C:\Users\Administrator\Documents\" -Force
```

### 2.5 Prepare Mimikatz Execution Environment

```powershell
# Disable LSASS protection (RunAsPPL)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0

# Windows Defender exclusion
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionExtension ".exe"

# Verify SeDebugPrivilege
whoami /priv  # SeDebugPrivilege must be Enabled
```

### 2.6 Create Logon Session (Mimikatz Target)

Enable Mimikatz to extract credentials by logging on with [TEST_DOMAIN_ADMIN] account:

```powershell
# Logon locally with [TEST_DOMAIN_ADMIN] (Console or RDP)
# Or maintain PowerShell remote session
$password = ConvertTo-SecureString "[TEST_DOMAIN_ADMIN_PASSWORD]" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("[YOUR_DOMAIN]\[TEST_DOMAIN_ADMIN]", $password)

# Maintain remote session (background)
$session = New-PSSession -ComputerName "[YOUR_DC_NAME]" -Credential $cred
```

---

## 🌐 3. Azure Resource Configuration

### 3.1 Azure AD Integration (For Phase 4 Authentication)

```powershell
# Install Azure AD Connect (Optional)
# Synchronize [TEST_DOMAIN_ADMIN]@[YOUR_DOMAIN] account to Azure AD

# Or manually create account in Azure AD
# UPN: [TEST_DOMAIN_ADMIN]@[YOUR_TENANT].onmicrosoft.com
```

### 3.2 Storage Account Configuration

| Item | Value |
|------|-------|
| **Name** | `[YOUR_STORAGE_ACCOUNT]` |
| **Container** | `sensitive-data` |
| **Access Key** | Key discovered in Phase 4 |

### 3.3 SQL Database Configuration

| Item | Value |
|------|-------|
| **Server Name** | `[YOUR_SQL_SERVER].database.windows.net` |
| **Database** | `[YOUR_SQL_DATABASE]` |
| **Administrator** | `[YOUR_SQL_USERNAME]` / `[YOUR_SQL_PASSWORD]` |

**Create Test Tables**:

```sql
-- Customers table (Sensitive data)
CREATE TABLE Customers (
    CustomerID INT PRIMARY KEY,
    FirstName NVARCHAR(50),
    LastName NVARCHAR(50),
    Email NVARCHAR(100),
    SSN NVARCHAR(11),  -- Sensitive information
    CreditCardNumber NVARCHAR(16)
);

INSERT INTO Customers VALUES
(1, 'John', 'Doe', 'john@example.com', '123-45-6789', '4111111111111111'),
(2, 'Jane', 'Smith', 'jane@example.com', '987-65-4321', '5500000000000004');

-- CreditCards table
CREATE TABLE CreditCards (
    CardID INT PRIMARY KEY,
    CardNumber NVARCHAR(16),
    CVV NVARCHAR(3),
    ExpiryDate DATE
);

-- Employees table
CREATE TABLE Employees (
    EmployeeID INT PRIMARY KEY,
    Name NVARCHAR(100),
    Department NVARCHAR(50),
    Salary DECIMAL(10,2)
);
```

---

## 🔧 4. Network Connectivity Verification

### 4.1 [YOUR_ATTACKER_HOST] → [YOUR_VM_NAME] Connection Test

```powershell
# Execute on [YOUR_ATTACKER_HOST]
Test-NetConnection -ComputerName [YOUR_VM_IP] -Port 445  # SMB
Test-NetConnection -ComputerName [YOUR_VM_IP] -Port 5985 # WinRM

# Credential test
$cred = Get-Credential  # [TEST_USER_1] / [TEST_PASSWORD_1]
New-PSSession -ComputerName [YOUR_VM_IP] -Credential $cred
```

### 4.2 [YOUR_VM_NAME] → [YOUR_DC_NAME] Connection Test

```powershell
# Execute on [YOUR_VM_NAME]
Test-NetConnection -ComputerName [YOUR_DC_IP] -Port 445
Test-NetConnection -ComputerName [YOUR_DC_IP] -Port 5985

# Domain account test
$cred = Get-Credential  # [YOUR_DOMAIN]\[TEST_DOMAIN_ADMIN] / [TEST_DOMAIN_ADMIN_PASSWORD]
New-PSSession -ComputerName [YOUR_DC_IP] -Credential $cred
```

---

## ✅ 5. Configuration Verification Checklist

### [YOUR_VM_NAME]
- [ ] IP address: [YOUR_VM_IP] configured
- [ ] [TEST_USER_1] / [TEST_PASSWORD_1] account created (Local Administrator)
- [ ] PowerShell Remoting enabled
- [ ] SMB C$ share accessible
- [ ] Windows Defender exclusion paths configured

### [YOUR_DC_NAME]
- [ ] IP address: [YOUR_DC_IP] configured
- [ ] Domain: [YOUR_DOMAIN] configured
- [ ] [TEST_DOMAIN_ADMIN] / [TEST_DOMAIN_ADMIN_PASSWORD] account created (Domain Admin)
- [ ] [TEST_USER_2], [TEST_USER_1] domain accounts created
- [ ] PowerShell Remoting enabled
- [ ] C:\Scripts\azure_config.txt file exists
- [ ] C:\Scripts\sql_config.txt file exists
- [ ] LSASS protection disabled
- [ ] [TEST_DOMAIN_ADMIN] logon session active

### Azure Resources
- [ ] Storage Account: [YOUR_STORAGE_ACCOUNT] created
- [ ] SQL Database: [YOUR_SQL_SERVER].database.windows.net created
- [ ] Customers table populated with sample data

---

## 🚨 Security Warning

**These configurations are intentionally vulnerable!**

- Weak passwords used ([TEST_PASSWORD_X])
- Windows Defender disabled
- PowerShell Remoting fully open
- LSASS protection disabled
- Sensitive information stored in plaintext

**NEVER apply these to production environments!**

These configurations should ONLY be used in **isolated test environments**:
- Network isolated from the Internet
- Azure test subscription (not production)
- Temporary VMs (delete after testing)

---

## 📚 References

- [Phase 2 Code](Phase2_Information_Gathering.ps1) - Brute force credential list
- [Phase 3 Code](Phase3_AD_Compromise.ps1) - AD account attempt list
- [Phase 4 Code](Phase4_Azure_Credential_Discovery.ps1) - File search paths
- [Attack Kill Chain Documentation](ATTACK_KILL_CHAIN.md) - Complete scenario flow
