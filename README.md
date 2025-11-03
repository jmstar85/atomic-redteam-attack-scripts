# 🔴 Atomic Red Team Attack Scripts for Azure Hybrid Cloud

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-Educational%20Use-yellow.svg)](LICENSE)
[![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-Compatible-green.svg)](https://github.com/redcanaryco/atomic-red-team)

A comprehensive collection of **PowerShell-based attack simulation scripts** designed to test and validate threat detection capabilities in **Azure Hybrid Cloud environments**. This project simulates a realistic multi-stage cyber attack chain from on-premises Active Directory compromise to Azure cloud resource exfiltration.

> ⚠️ **EDUCATIONAL PURPOSES ONLY** - These scripts are designed for security testing in isolated lab environments. Unauthorized use against production systems is illegal and unethical.

---

## 🎯 Overview

This project implements a complete **Cyber Kill Chain** targeting hybrid cloud infrastructure, demonstrating how attackers can:
- Compromise on-premises Active Directory environments
- Perform lateral movement across network boundaries
- Extract cloud credentials from compromised systems
- Breach Azure Storage and SQL Database resources
- Exfiltrate sensitive data through multiple channels

The attack chain is mapped to the **MITRE ATT&CK Framework** and integrates with **Atomic Red Team** for standardized security testing.

---

## ✨ Key Features

### 🔍 **Comprehensive Attack Simulation**
- **9 Phases** covering the entire attack lifecycle (Initial Access → Data Exfiltration → Cleanup)
- **15+ MITRE ATT&CK Techniques** implemented (T1046, T1087, T1110, T1552, T1530, etc.)
- **Atomic Red Team Integration** for standardized test execution
- **Realistic Scenarios** including brute force, credential dumping, lateral movement, and cloud resource exploitation

### 🌐 **Hybrid Cloud Focus**
- **On-Premises → Cloud** attack path simulation
- **Active Directory** compromise and credential harvesting (Mimikatz)
- **Azure Storage Account** enumeration and data exfiltration
- **Azure SQL Database** breach and sensitive data extraction
- **Multi-channel Exfiltration** (DNS Tunneling, HTTPS, Scheduled Tasks)

### 🛡️ **Security-First Design**
- **No Hardcoded Credentials** - All sensitive values use placeholders
- **Configurable Parameters** - Easy customization via command-line arguments
- **Safety Features** - Built-in environment validation and admin checks
- **Automatic Cleanup** - Phase 8 restores Defender and removes artifacts
- **Simulation Mode** - Data exfiltration requires explicit environment variable activation

### 📊 **Comprehensive Logging**
- **JSON Output** for each phase with timestamps and results
- **Detailed Console Output** with color-coded status messages
- **Attack Timeline** generation for forensic analysis
- **Credential Extraction Reports** with risk levels (HIGH/MEDIUM)

### 🔧 **Easy Setup & Automation**
- **Automatic Atomic Red Team Installation** in Phase 0
- **Configuration Validation** to detect placeholder values
- **Single-Command Execution** via `99_Run_All.ps1`
- **Detailed Setup Guide** ([VM_SETUP_GUIDE.md](VM_SETUP_GUIDE.md))

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      ATTACK KILL CHAIN                          │
└─────────────────────────────────────────────────────────────────┘

Phase 0: Environment Verification
    ↓ (Atomic Red Team Setup)
Phase 1: Initial Reconnaissance (T1046, T1087)
    ↓ (Network Scanning, Account Enumeration)
Phase 2: Information Gathering & Lateral Movement (T1021.001)
    ↓ (Pivot to vmjarvisfe)
Phase 3: AD Server Compromise (T1110, Mimikatz)
    ↓ (Credential Dumping)
Phase 4: Azure Credential Discovery (T1552.001)
    ↓ (File Search, Azure Auth)
Phase 5: Storage Account Breach (T1530)
    ↓ (Blob Enumeration)
Phase 6: SQL Database Breach (T1213)
    ↓ (Sensitive Data Extraction)
Phase 7: Multi-Channel Data Exfiltration (T1048, T1041)
    ↓ (DNS, HTTPS, Scheduled Tasks)
Phase 8: Cleanup & Evasion (T1070)
    ↓ (Log Deletion, Timestamp Manipulation, Defender Restore)
```

---

## 📁 Project Structure

```
Attack_Scripts_dist/
├── 00_Initialize.ps1                      # Global configuration setup
├── Phase0_Environment_Check.ps1           # Prerequisites validation
├── Phase1_Reconnaissance.ps1              # Network discovery
├── Phase2_Information_Gathering.ps1       # Lateral movement
├── Phase3_AD_Compromise.ps1               # AD credential extraction
├── Phase4_Azure_Credential_Discovery.ps1  # Cloud credential search
├── Phase5_Storage_Breach.ps1              # Azure Storage attack
├── Phase6_SQL_Breach.ps1                  # SQL Database attack
├── Phase7_Data_Exfiltration.ps1           # Multi-channel exfiltration
├── Phase8_Cleanup.ps1                     # Artifact removal
├── 99_Run_All.ps1                         # Automated full execution
├── VM_SETUP_GUIDE.md                      # Infrastructure setup guide
└── README.md                              # This file
```

---

## 🚀 Quick Start

### Prerequisites

- **Windows 10/11** or **Windows Server 2016+** (PowerShell 5.1+)
- **Administrator Privileges** required
- **Isolated Lab Environment** (no production systems!)
- **Test Infrastructure** (see [VM_SETUP_GUIDE.md](VM_SETUP_GUIDE.md))

### Step 1: Clone Repository

```powershell
git clone https://github.com/jmstar85/atomic-redteam-attack-scripts.git
cd atomic-redteam-attack-scripts
```

### Step 2: Configure Environment

Edit parameters in `00_Initialize.ps1` or pass them via command line:

```powershell
.\00_Initialize.ps1 `
    -TargetDC_IP "192.168.1.10" `
    -TargetVM_IP "192.168.1.20" `
    -TargetDC_Name "DC01" `
    -TargetVM_Name "Client01" `
    -Domain "lab.local" `
    -StorageAccount "teststore123" `
    -SQLServer "testsql-server"
```

### Step 3: Run Attack Simulation

**Option A: Execute All Phases Automatically**
```powershell
.\99_Run_All.ps1
```

**Option B: Execute Phases Individually**
```powershell
.\Phase0_Environment_Check.ps1  # Auto-installs Atomic Red Team
.\Phase1_Reconnaissance.ps1
.\Phase2_Information_Gathering.ps1
# ... continue with remaining phases
```

### Step 4: Review Results

```powershell
# Logs are saved to:
# C:\AtomicTest\Logs\Attack_<timestamp>\

# View attack summary
Get-Content C:\AtomicTest\Logs\Attack_*\phase8_final_report.json | ConvertFrom-Json
```

---

## 🎓 MITRE ATT&CK Mapping

| Phase | Technique ID | Technique Name | Description |
|-------|--------------|----------------|-------------|
| **Phase 1** | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Port scanning (445, 3389, 389, 88, 135) |
| **Phase 1** | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account Discovery | Enumerate domain users via `net user /domain` |
| **Phase 2** | [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Identify LSASS and other key processes |
| **Phase 2** | [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Collect OS, hardware, and environment data |
| **Phase 2** | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Search for scripts, configs, and documents |
| **Phase 2** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral movement via PowerShell Remoting |
| **Phase 3** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential brute force against AD accounts |
| **Phase 3** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Mimikatz credential dumping |
| **Phase 4** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files | Search for Azure/SQL credentials in scripts |
| **Phase 5** | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | Enumerate and access Azure Blob Storage |
| **Phase 6** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | SQL Server authentication |
| **Phase 6** | [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Extract sensitive database records |
| **Phase 7** | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Alternative Protocol: DNS | DNS tunneling for metadata |
| **Phase 7** | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | HTTPS data exfiltration |
| **Phase 7** | [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Scheduled task for persistence |
| **Phase 8** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs | Event log deletion |
| **Phase 8** | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Indicator Removal: Timestomp | File timestamp manipulation |
| **Phase 8** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | Remove Mimikatz and artifacts |

---

## 🔐 Security Considerations

### ⚠️ **WARNING: INTENTIONALLY VULNERABLE**

This project creates **deliberately insecure configurations** for testing purposes:

- ❌ Weak passwords (for brute force testing)
- ❌ Windows Defender disabled
- ❌ LSASS protection disabled
- ❌ PowerShell Remoting fully open
- ❌ Credentials stored in plaintext files

### ✅ **Safe Usage Guidelines**

1. **Isolated Environment Only**
   - Use air-gapped networks or separate VLANs
   - No connection to production systems
   - Azure test subscriptions only (not production tenants)

2. **Temporary Infrastructure**
   - Deploy VMs specifically for testing
   - **Delete all resources** after testing
   - Do not reuse test credentials elsewhere

3. **Legal & Ethical**
   - Obtain written authorization before testing
   - Only test systems you own or have explicit permission to test
   - Understand applicable laws (e.g., Computer Fraud and Abuse Act)

4. **Monitoring & Detection**
   - Use this as a **Blue Team training tool**
   - Configure SIEM/EDR to detect these techniques
   - Document detection gaps and improve defenses

---

## 📚 Documentation

- **[VM_SETUP_GUIDE.md](VM_SETUP_GUIDE.md)** - Detailed infrastructure setup instructions
- **Phase Script Comments** - Inline documentation for each attack technique
- **JSON Logs** - Structured output for analysis (`C:\AtomicTest\Logs\`)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-technique`)
3. Commit changes with clear messages
4. Submit a Pull Request with detailed description

**Ideas for Contributions:**
- Additional MITRE ATT&CK techniques
- Detection rule generation (Sigma, KQL, Splunk)
- Automated report generation
- Docker/VM automation scripts
- Blue Team playbooks

---

## 📄 License

**Copyright (c) 2025 jmstar85. All rights reserved.**
**
This software and associated documentation files (the "Software") are the exclusive property of jmstar85. All rights, title, and interest in and to the Software are owned by jmstar85.**

**Terms of Use**

This project is provided for educational and research purposes only.

**Copyright Protection**

Unauthorized copying, distribution, modification, or use of this Software, in whole or in part, is strictly prohibited without explicit written permission from the copyright owner.
Any violation of these terms may result in legal action and you may be subject to civil and criminal penalties under applicable copyright laws.
All intellectual property rights, including but not limited to copyrights, patents, and trade secrets, remain with jmstar85.
Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM THE USE OF THE SOFTWARE.

For licensing inquiries or permission requests, please contact the repository owner.


**Disclaimer:** The author assumes no liability for misuse of this software. Users are solely responsible for ensuring compliance with all applicable laws and regulations.

---

## 🙏 Acknowledgments

- **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** by Red Canary - Test framework foundation
- **[MITRE ATT&CK](https://attack.mitre.org/)** - Adversary tactics and techniques taxonomy
- **[Mimikatz](https://github.com/gentilkiwi/mimikatz)** by Benjamin Delpy - Credential extraction research
- **PowerShell Community** - Scripting best practices and modules

---

## 📧 Contact & Support

- **Author:** jmstar85
- **GitHub:** [@jmstar85](https://github.com/jmstar85)
- **Issues:** [Report bugs or request features](https://github.com/jmstar85/atomic-redteam-attack-scripts/issues)

---

## 🔍 Related Projects

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Comprehensive security testing framework
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) - PowerShell module for test execution
- [Purple Team ATT&CK Automation](https://github.com/praetorian-inc/purple-team-attack-automation) - Similar purple teaming tools
- [BadBlood](https://github.com/davidprowe/BadBlood) - AD environment population for testing

---

<div align="center">

**⭐ Star this repository if you find it useful!**

Made with ❤️ for the cybersecurity community

</div>


