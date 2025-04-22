# 🛡️ Threat Hunt: Zero-Day Ransomware (PwnCrypt) on Windows VM

**Author:** James Moore  
**Date:** April 21, 2025  
**Lab Type:** Threat Hunting / Ransomware Detection / MITRE ATT&CK Mapping  

---

## 🧠 Scenario Overview

A new ransomware variant called **PwnCrypt** has been discovered in the wild. It utilizes a PowerShell payload that encrypts files using AES-256, renaming files with a `.pwncrypt` extension. Suspicious activity was detected on the `win10vm` endpoint. This lab walks through identifying, investigating, and mitigating the threat.

---

## 📊 Step 1: File Creation Detection

Check for creation of the known malicious script `pwncrypt.ps1`.

```kql
let VMName = "win10vm";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt.ps1"
| order by Timestamp desc
```

📸 **DeviceFileEvents with `pwncrypt.ps1**

<img width="750" alt="Screen Shot 2025-04-21 at 9 43 59 PM" src="https://github.com/user-attachments/assets/c771b7b8-b9cb-410d-a836-2ff6bfb52294" />

---

## 🔍 Step 2: Trace Processes Around File Creation

Investigate the process activity around the time the script was created.

```kql
let VMName = "win10vm";
let specificTime = datetime(2025-04-21T23:17:02.8357585Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where ProcessCommandLine has "pwncrypt.ps1"
   or InitiatingProcessCommandLine has "pwncrypt.ps1"
   or FileName == "powershell.exe"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

📸 **PowerShell and CMD.exe launch chains with `cyberlab123` account**  

<img width="750" alt="Screen Shot 2025-04-21 at 10 39 47 PM" src="https://github.com/user-attachments/assets/d8b849e2-a463-4735-bf71-5b24b39da955" />

---

## 🧬 Step 3: Detect Encoded PowerShell Commands

Search for suspicious base64-encoded PowerShell payloads (T1059.001).

```kql
let VMName = "win10vm";
DeviceProcessEvents
| where DeviceName == VMName
| where ProcessCommandLine has "-EncodedCommand"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

📸 **-EncodedCommand`**  

<img width="800" alt="Screen Shot 2025-04-21 at 10 42 16 PM" src="https://github.com/user-attachments/assets/bad60259-13e8-470f-8bfa-3c99e1ce06a0" />

---

## 🔓 Decoded Payload Example

This payload was identified and decoded:

### 🔐 Encoded:
```
-encodedCommand IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA=
```

### 🧾 Decoded:
```powershell
[Environment]::OSVersion.Version
```

This suggests a sandbox or system profiling technique often used by ransomware to evade detection.

---

## 🧰 Additional Queries (Optional Enhancements)

### Detect files with `.pwncrypt` extensions:
```kql
DeviceFileEvents
| where DeviceName == "win10vm"
| where FileName contains ".pwncrypt"
| order by Timestamp desc
```

### Detect use of Bypass policy (ExecutionPolicy Tactic):
```kql
DeviceProcessEvents
| where DeviceName == "win10vm"
| where ProcessCommandLine has "ExecutionPolicy Bypass"
| order by Timestamp desc
```

---

## 🩱 MITRE ATT&CK Mapping

| Tactic              | Technique ID     | Description                               |
|---------------------|------------------|-------------------------------------------|
| Execution           | T1059.001        | PowerShell execution                      |
| Defense Evasion     | T1216            | EncodedCommand / PolicyBypass             |
| Discovery           | T1082 / T1518    | System profiling with OS checks           |
| Impact              | T1486            | Ransomware file encryption                |

---

✅ **Recommendations:**
- Block use of `-EncodedCommand` unless explicitly needed.
- Enforce AppLocker policies to deny script execution from non-standard directories.
- Enable Microsoft Sentinel alerts for anomalous PowerShell usage.
- Monitor for CMD > PowerShell > Script chains initiated by non-admin users.

---

🌟 **Status:** Investigation completed and threat mitigated. Endpoint isolated, account disabled, and IOCs logged for continued detection.

