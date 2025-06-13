
# 🛡️ Cyberattacks & Malware Analysis Lab

This project focuses on hands-on cyberattack investigation techniques, including **email header analysis**, **malware analysis**, and usage of threat intelligence platforms like **VirusTotal**, **IBM X-Force**, and **Hybrid Analysis**.

---

## ✉️ Task 1: Email Header Analysis (Phishing Detection)

### Indicators of Compromise (IOCs)
- **IP:** 17.50.10.134  
- **Domain:** maxsgmail.top  
- **URL:** https://dtec.com.my/ash?email=ad@malware-traffic-analysis.net  
- **SHA256 Hash:** b264818bdfa95e0498fcc48734a9e40921e15d8d389294a703094e9691905de6

### Analysis:
- 🔍 **IP Check**: Verified on VirusTotal and IBM X-Force – no malicious detection.
- 🌐 **Domain Check**: Domain flagged as unknown risk, no DNS record.
- 🔗 **Hyperlink Check**: Detected as **malicious** by 5 vendors (3 phishing, 2 malware).
- 🔐 **Hash Check**: No detection on VirusTotal; IBM X-Force classifies it as a SHA256 hash.

✅ **Conclusion**: The email is a **phishing email**, flagged based on malicious URL behavior.

---

## 🦠 Task 2: Malware File Analysis

### Sample 1: `Compliant_29769200-352` (Java Script)
- Opened in Sublime Text, saved as `.java`.
- ✅ **VirusTotal**: Flagged by 30 vendors + 1 sandbox.
- ✅ **IBM X-Force**: High-risk, SHA256 hash detected.
- ✅ **Hybrid Analysis**: Malicious behavior and related files confirmed.
- **Conclusion**: Malicious Java-based malware.

---

### Sample 2: `ImportantSign_PDF` (PDF Trojan)
- ✅ **VirusTotal**: Flagged by 33 vendors.
- ✅ **IBM X-Force**: High-risk MD5 hash, classified as **Trojan**.
- ✅ **Hybrid Analysis**: Shows ransomware behavior, persistence, and remote access.
- **MITRE ATT&CK Techniques Identified**:
  - **Execution**: Visual Basic, Windows Shell, WMI
  - **Persistence & Privilege Escalation**: Registry Keys, Process Injection

📌 **Conclusion**: File is confirmed as **trojan malware**, showing multiple attack tactics.

---

### Sample 3: `StolenImages` (JS Trojan)
- ✅ **VirusTotal**: Flagged by 21 vendors and 2 sandboxes.
- ✅ **IBM X-Force**: High-risk, flagged as **Trojan**.
- ✅ **Hybrid Analysis**: Threat score 100/100.
- **MITRE ATT&CK Techniques**:
  - PowerShell Execution
  - Command-Line Interface
  - Hooking (for persistence, privilege escalation)
  - Process Injection (for evasion and privilege escalation)

📌 **Conclusion**: Infected JavaScript file performing high-risk trojan behavior.

---

## 🧠 Learning Outcome

- Analyzed phishing emails using IOCs.
- Identified and verified malware using industry-grade tools.
- Mapped techniques using MITRE ATT&CK.
- Used threat intel platforms for hash, IP, and domain investigation.

---

## 🧰 Tools Used
- [VirusTotal](https://www.virustotal.com)
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com)
- [Hybrid Analysis](https://www.hybrid-analysis.com)
