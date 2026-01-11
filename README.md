
# January06ThreatHunt
Incident Response Report from Threat Hunt

<img width="522" height="793" alt="Screenshot 2026-01-11 at 12 50 08 PM" src="https://github.com/user-attachments/assets/dae1e91b-ec95-41c8-9d9e-3326e90b9d68" />


---

## 📝 INCIDENT RESPONSE REPORT

**Date of Report:** 2026-01-06  
**Incident Date Range:** 2025-11-19 – 2025-12-06  
**Severity Level:** HIGH  
**Report Status:** Open  
**Escalated To:** Incident Response / Ransomware Response Team  
**Incident ID:** AZUKI-2025-RANSOMWARE-PREP  
**Analyst:** Brian Sanford  

---

## 📌 SUMMARY OF FINDINGS

- On **2025-11-27**, ransom notes were discovered across multiple systems, confirming a successful ransomware event.
- Investigation determined the attackers intentionally delayed ransomware execution while **systematically eliminating backup and recovery capabilities**.
- Attackers pivoted from compromised Windows systems to a **Linux-based backup server**, leveraging **SSH access** with the privileged account **backup-admin**.
- Extensive **discovery and reconnaissance** targeted backup directories, scheduled jobs, local accounts, and credential storage locations.
- External tooling (`destroy.7z`) was downloaded to facilitate destructive operations.
- **All enterprise backup repositories were deleted**, including daily, weekly, monthly, database, workstation, and configuration backups.
- Backup services were **stopped and disabled**, ensuring destruction persisted across reboots.
- Following backup eradication, attackers used **PsExec** to rapidly deploy ransomware across Windows systems.
- Recovery was actively inhibited through **shadow copy deletion, backup engine shutdown, service termination, and recovery environment disabling**.
- Persistence mechanisms were established using **registry autoruns** and **scheduled tasks**.
- Anti-forensic activity included **USN journal deletion**, degrading forensic reconstruction.
- The attack concluded with encryption and deployment of the ransom note **SILENTLYNX_README.txt**, confirming ransomware success.

---

## 👤 WHO

### Attacker Activity Sources
- **Initial Pivot Host:** azuki-adminpc  
- **Backup Infrastructure:** BackupSrv  
- **Windows Deployment Targets:** Multiple azuki-* systems  

### Compromised Accounts
- **backup-admin** (Linux backup administrator)
- **kenji.sato** (Windows domain account – ransomware deployment)
- **yuki.tanaka** (Windows account – recovery inhibition)

---

## 📂 WHAT (Event Summary)

## 🚩 Flags & Indicators of Compromise (IOCs)

| Flag # | Category | Indicator | Timestamp |
|------:|---------|-----------|-----------|
| 1 | Remote Access | `ssh.exe backup-admin@10.1.0.189` | 2025-11-25T05:39:10Z |
| 2 | Lateral Movement Source | 10.1.0.108 | 2025-11-25T05:39:22Z |
| 3 | Compromised Account | backup-admin | 2025-11-25 |
| 4 | Backup Enumeration | `ls -la /backups/` | 2025-11-25T05:41:43Z |
| 5 | Archive Discovery | `find /backups -name *.tar.gz` | 2025-11-24T14:16:06Z |
| 6 | Account Enumeration | `cat /etc/passwd` | 2025-11-24T14:16:08Z |
| 7 | Scheduled Job Recon | `cat /etc/crontab` | 2025-11-24T14:16:08Z |
| 8 | Tool Download | `destroy.7z` | 2025-11-25T05:45:34Z |
| 9 | Credential Access | `all-credentials.txt` | 2025-11-24T14:14:14Z |
| 10 | Backup Destruction | `rm -rf /backups/*` | 2025-11-25T05:47:02Z |
| 11 | Service Stop | `systemctl stop cron` | 2025-11-25T05:47:03Z |
| 12 | Service Disable | `systemctl disable cron` | 2025-11-25T05:47:03Z |
| 13 | Remote Execution | PsExec64.exe | 2025-11-25T05:58:35Z |
| 14 | Ransomware Deployment | silentlynx.exe | 2025-11-25 |
| 15 | Payload Execution | silentlynx.exe | 2025-11-25 |
| 16 | Shadow Copy Stop | `net stop vss` | 2025-11-25T06:04:53Z |
| 17 | Backup Engine Stop | `net stop wbengine` | 2025-11-25T06:04:54Z |
| 18 | Process Termination | `taskkill /IM sqlservr.exe` | 2025-11-25T06:04:57Z |
| 19 | Shadow Deletion | `vssadmin delete shadows` | 2025-11-25T05:58:55Z |
| 20 | Storage Limitation | `vssadmin resize shadowstorage` | 2025-11-25 |
| 21 | Recovery Disabled | `bcdedit recoveryenabled No` | 2025-11-25T06:04:59Z |
| 22 | Catalog Deletion | `wbadmin delete catalog` | 2025-11-25T06:04:59Z |
| 23 | Registry Autorun | WindowsSecurityHealth | 2025-11-25T06:05:01Z |
| 24 | Scheduled Task | SecurityHealthService | 2025-11-25T06:05:01Z |
| 25 | Anti-Forensics | `fsutil usn deletejournal` | 2025-11-25T06:10:04Z |
| 26 | Ransom Note | SILENTLYNX_README.txt | 2025-11-25T06:05:01Z |

---

## ⏱ WHEN (UTC Timeline)

- **11-24:** Backup discovery and credential harvesting  
- **11-25 05:39:** SSH access to backup server  
- **11-25 05:47:** Backup destruction completed  
- **11-25 05:58:** Ransomware deployed via PsExec  
- **11-25 06:04:** Recovery mechanisms disabled  
- **11-25 06:05:** Persistence established  
- **11-25 06:10:** Anti-forensics executed  
- **11-27:** Ransom notes discovered enterprise-wide  

---

## 🖥 WHERE (Infrastructure Impact)

### Compromised Systems
- azuki-adminpc  
- BackupSrv  
- Multiple Windows azuki-* systems  

### Destroyed Backup Locations
- /backups/daily  
- /backups/weekly  
- /backups/monthly  
- /backups/databases  
- /backups/workstations  
- /backups/configs  

---

## ❓ WHY (Attacker Motivation & Root Cause)

### Root Cause
- Privileged account compromise with direct access to backup infrastructure.
- Insufficient segmentation between production and recovery assets.
- Backup servers accessible using standard administrative credentials.

### Attacker Objectives
- Eliminate recovery options  
- Guarantee ransomware leverage  
- Accelerate encryption  
- Prevent rollback or restoration  

### Business Impact
- Complete loss of on-site backups  
- Severe MTTR degradation  
- Extended operational outage risk  

---

## ⚙️ HOW (Attack Chain Summary)

1. Initial Windows compromise  
2. Pivot to Linux backup server via SSH  
3. Enumeration of backups, schedules, and credentials  
4. External tool download  
5. Complete backup destruction  
6. Backup service disablement  
7. Ransomware deployment via PsExec  
8. Recovery inhibition  
9. Persistence and anti-forensics  
10. Encryption and ransom note delivery  

---

## 🚨 IMPACT ASSESSMENT

### Actual Impact
- Backup infrastructure destroyed  
- Enterprise ransomware deployment  
- Recovery mechanisms disabled  
- Forensic visibility reduced  

### Risk Level
**CRITICAL**

---

## 🛠 RECOMMENDATIONS

### 🔥 IMMEDIATE
- Isolate affected systems  
- Disable compromised accounts  
- Engage ransomware response  
- Preserve remaining forensic artifacts  

---

## 🛡 LONG-TERM RECOMMENDATIONS

- Implement immutable backups  
- Enforce MFA for backup/admin access  
- Segment recovery infrastructure  
- Monitor SSH and PsExec usage  
- Conduct ransomware tabletop exercises  



---
## Jan 6 Threat Hunt – Ransomware Kill Chain (Azuki Logistics)

---

### Flag 1 – Initial Access: Remote SSH Activity

**Use Case:**  
Identify secure shell–based access from a Windows endpoint used to pivot into Linux backup infrastructure.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "azuki-adminpc"
| where FileName in~ ("ssh.exe","scp.exe","sftp.exe","plink.exe")
   or ProcessCommandLine has "ssh "

---

### Flag 2 – Lateral Movement: Attack Source Identification

**Use Case:**  
Correlate authentication events to identify the originating host used to access the backup server.

DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where LogonType == "Network"
| where AccountName == "backup-admin"

---

### Flag 3 – Credential Access: Compromised Backup Account

**Use Case:**  
Confirm abuse of a privileged backup account used to access recovery-critical systems.

DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "backup-admin"

---

### Flag 4 – Discovery: Directory Enumeration

**Use Case:**  
Detect file system reconnaissance used to locate backup directories and critical data stores.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "backup-admin"
| where ProcessCommandLine has_any (
    "ls",
    "tree",
    "find ",
    "locate ",
    "dir ",
    "show flash",
    "nvram"
)
| project TimeGenerated, ProcessCommandLine

---

### Flag 5 – Discovery: Backup Archive Identification

**Use Case:**  
Identify searches for compressed backup archives likely targeted for destruction or exfiltration.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ProcessCommandLine contains "find /backups"
| where ProcessCommandLine contains ".tar.gz"
| project TimeGenerated, ProcessCommandLine

---

### Flag 6 – Discovery: Local Account Enumeration

**Use Case:**  
Detect enumeration of local Linux accounts to identify additional targets or escalation paths.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine has "/etc/passwd"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 7 – Discovery: Scheduled Job Reconnaissance

**Use Case:**  
Identify reconnaissance of cron jobs to understand backup timing and persistence mechanisms.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "cron"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 8 – Command and Control: Tool Download

**Use Case:**  
Detect external tool downloads used to stage destructive or ransomware-related utilities.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where FileName has_any ("curl", "wget")
| project TimeGenerated, ProcessCommandLine

---

### Flag 9 – Credential Access: Credential File Theft

**Use Case:**  
Identify access to plaintext or sensitive credential files stored within backup configurations.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine has_any (
    "/etc/shadow",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/authorized_keys",
    "credentials",
    "secrets"
)
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 10 – Impact: Backup Data Destruction

**Use Case:**  
Detect deletion of backup repositories intended to eliminate recovery options prior to ransomware deployment.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine has_any ("rm","del")
| where ProcessCommandLine contains "backup"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 11 – Impact: Service Stopped

**Use Case:**  
Identify immediate service disruption actions used to halt scheduled backup operations.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine has_any ("stop")
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 12 – Impact: Service Disabled

**Use Case:**  
Detect disabling of services to ensure backup operations do not resume after reboot.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine has_any ("stop","kill","disable")
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 13 – Lateral Movement: Remote Execution via PsExec

**Use Case:**  
Detect remote execution tooling used to deploy ransomware across Windows systems.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where FileName =~ "psexec.exe" or ProcessCommandLine contains "psexec"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 14 – Lateral Movement: Ransomware Deployment Command

**Use Case:**  
Capture full deployment commands revealing targeted hosts, credentials, and malicious payloads.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ProcessCommandLine contains "PsExec"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 15 – Execution: Ransomware Payload Identification

**Use Case:**  
Identify the malicious executable responsible for encryption activity.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ProcessCommandLine contains "silentlynx.exe"
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 16 – Impact: Shadow Copy Service Stopped

**Use Case:**  
Detect attempts to stop Volume Shadow Copy Services to prevent recovery.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ProcessCommandLine has_any ("net stop", "sc stop", "vss")
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 17 – Impact: Backup Engine Disabled

**Use Case:**  
Identify commands stopping Windows backup engines to prevent ongoing protection.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine has_any ("net","sc","vss")
| project TimeGenerated, AccountName, ProcessCommandLine

---

### Flag 18 – Defense Evasion: Process Termination

**Use Case:**  
Detect forced termination of processes that lock files prior to encryption.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "taskkill"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 19 – Impact: Shadow Copy Deletion

**Use Case:**  
Identify deletion of recovery points to permanently remove restore options.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "shadows"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 20 – Impact: Shadow Storage Limitation

**Use Case:**  
Detect resizing of shadow storage to prevent new recovery points from being created.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where ProcessCommandLine contains "shadowstorage"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 21 – Impact: Recovery Disabled

**Use Case:**  
Identify disabling of Windows recovery mechanisms to prevent automated repair.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "bcdedit"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 22 – Impact: Backup Catalog Deletion

**Use Case:**  
Detect deletion of backup catalogs that track available restore points.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "wbadmin"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 23 – Persistence: Registry Autorun

**Use Case:**  
Identify registry-based persistence mechanisms executed at system startup.

DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where DeviceName == "azuki-adminpc"

---

### Flag 24 – Persistence: Scheduled Task Execution

**Use Case:**  
Detect scheduled task creation or execution used to maintain persistence.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where FileName contains "schtasks"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 25 – Defense Evasion: USN Journal Deletion

**Use Case:**  
Detect deletion of NTFS change journals to hinder forensic reconstruction.

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "fsutil"
| project TimeGenerated, FileName, AccountName, ProcessCommandLine

---

### Flag 26 – Impact: Ransom Note Creation

**Use Case:**  
Identify ransom note files indicating successful encryption and attack completion.

DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))
| where FileName contains ".txt"
| project TimeGenerated, FileName, FolderPath

---


Azuki Logistics
