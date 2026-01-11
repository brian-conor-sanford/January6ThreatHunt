
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

## 📎 APPENDIX A — MITRE ATT&CK Mapping
*(To be expanded)*

## 📎 APPENDIX B — KQL DETECTIONS
*(To be expanded)*

## 📎 APPENDIX C — RECOVERY & MTTR ANALYSIS
*(To be expanded)*

Azuki Logistics
