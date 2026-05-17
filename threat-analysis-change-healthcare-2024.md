# Threat Analysis: Change Healthcare Ransomware Attack (2024)

### SOC Analyst Perspective: Alert Triage and Incident Reasoning

**Analyst:** Mateus Dias
**Analysis Date:** 2026-05-17
**Case Type:** Real-world incident case study, triage simulation
**Incident Period:** February 12 to February 21, 2024
**Discovery:** February 21, 2024 (Change Healthcare internal detection)

---

## Preface

This document reconstructs the Change Healthcare ransomware attack from the perspective of a SOC analyst receiving alerts in real time, before the incident was publicly known. The goal is to document the triage reasoning applied to each alert as it appeared, identify the detection opportunities that were missed, and extract lessons applicable to modern SOC operations.

The alerts below are based on publicly documented indicators from congressional testimony, HIPAA breach disclosures, and post-incident forensic reporting. The triage reasoning is my own, applied without prior knowledge of the outcome.

---

## Incident Background

In February 2024, an affiliate of the ALPHV/BlackCat ransomware-as-a-service group compromised Change Healthcare, a subsidiary of UnitedHealth Group and the largest healthcare claims processing company in the United States. The company processes approximately 15 billion healthcare transactions annually, touching one in every three patient records in the country.

The entry vector was shockingly simple: a Citrix remote access portal without multi-factor authentication. The attacker used a single set of compromised credentials later traced to an infostealer infection to log into the portal at 03:47 EST on February 12. Over the following nine days, the attacker moved laterally through the network, performed credential dumping, exfiltrated approximately 6TB of protected health information, and deployed BlackCat ransomware on February 21, taking down claims processing, prior authorization, and pharmacy operations for approximately 70% of U.S. pharmacies and 40% of U.S. hospitals.

UnitedHealth Group CEO Andrew Witty confirmed in congressional testimony that the missing MFA was the critical failure that allowed the attack to succeed. The credential used had never been updated following the company's acquisition of Change Healthcare in October 2022.

Total financial impact reached approximately $2.457 billion through Q3 2024. The breach affected an estimated 190 million Americans the largest healthcare data breach in U.S. history.

---

## Alert Timeline and Triage Reasoning

---

### Alert 1 | February 12, 2024 | 03:47 EST

```
RULE:    AUTH_REMOTE_GEO_ANOMALY_001
SOURCE:  citrix_access_logs
LEVEL:   CRITICAL

User:           svc_remoteaccess04
Auth result:    SUCCESS
Source IP:      185.220.101.47
Geo (IP):       Frankfurt, DE Tor exit node (flagged)
Usual geo:      Nashville, TN, US
Portal:         remoteapps.changehealthcare.com
MFA status:     NOT CONFIGURED on this account
Device:         Unknown not in approved device list
Session:        ACTIVE currently connected
Time:           03:47 EST outside business hours
```

**My triage reasoning:**

This is not a single suspicious indicator. It is five simultaneous red flags arriving in the same event: anomalous login time, geolocation mismatch, IP associated with a Tor exit node, unrecognized device, and an account with no MFA configured.

Each of these in isolation could have an innocent explanation. An employee traveling abroad using a VPN could explain the geolocation mismatch. An odd login time could be explained by remote work across time zones. But the combination removes ambiguity. A legitimate user traveling internationally would still be expected to authenticate from a known device. A known device would not present as a Tor exit node. And if any of this were planned, there would be a ticket.

There is no open ticket. There is no approved change request. The session is active right now.

The most important detail here is operational: every minute this session remains active is a minute the attacker has inside the environment. The cost of a false positive a legitimate user loses access for a few minutes and opens a ticket is negligible. The cost of a false negative is a live intrusion left uncontained.

**Decision:** Immediate escalation to Tier 2. Flag session CTX-8847FA02 for emergency review and containment. If authorized, terminate the session now. Do not wait for confirmation before escalating escalate and investigate simultaneously.

**MITRE ATT&CK:**
- T1078 Valid Accounts
- T1133 External Remote Services

---

### Alert 2 | February 12, 2024 | 04:09 EST

```
RULE:    INTERNAL_RECON_SMB_SWEEP_004
SOURCE:  network_ids, windows_event_logs
LEVEL:   HIGH

Origin:         CITRIX-HOST-07 (session CTX-8847FA02)
User:           svc_remoteaccess04
Activity:       SMB sweep 142 hosts scanned in 21 minutes
Ports targeted: 445 (SMB), 135 (RPC), 3389 (RDP)
Hosts responded: 38 of 142 including DB-PROD-01, DB-PROD-03
Tools detected: net.exe, nltest.exe, arp -a (LOLBins)
Parent process: cmd.exe → net.exe / nltest.exe
Change ticket:  NONE
Relation:       Same session as Alert #1
```

**My triage reasoning:**

Twenty-two minutes after the initial login, the same session is now sweeping 142 internal hosts. This is not human behavior. A legitimate user does not enumerate 142 machines in 21 minutes. This is scripted, automated reconnaissance the discovery phase of a structured attack.

The port selection tells the story precisely. Port 445 is SMB: lateral movement, file share access, credential relay. Port 135 is RPC: service enumeration, mapping what is running where. Port 3389 is RDP: identifying machines available for remote desktop takeover. This is not random curiosity. This is a deliberate map being drawn before the next move.

The tools are equally telling. `net.exe` and `nltest.exe` are native Windows binaries. Using them is a Living off the Land technique no external tools installed, no malware signatures to trigger, no antivirus alerts. `nltest /domain_trusts` specifically queries Active Directory trust relationships, which tells the attacker which domains they can pivot to from their current position.

The most alarming detail: DB-PROD-01 and DB-PROD-03 are among the 38 hosts that responded. These are production database servers. A support account with no business reason to access them has just confirmed they are reachable.

This alert, combined with Alert 1, is no longer noise. This is an active intrusion in progress.

**Decision:** Escalate immediately. Present the full two-alert chain to Tier 2 and request war room activation. The attacker is mapping the network from a session that should have been terminated 22 minutes ago. Every additional minute increases the attack surface they can reach.

**MITRE ATT&CK:**
- T1018 Remote System Discovery
- T1021.002 Remote Services: SMB/Windows Admin Shares
- T1482 Domain Trust Discovery
- T1059.003 Command and Scripting Interpreter: Windows Command Shell

---

### Alert 3 | February 12, 2024 | 04:31 EST

```
RULE:    LSASS_DUMP_ATTEMPT_007
SOURCE:  windows_event_logs, edr_telemetry
LEVEL:   CRITICAL

Host:           DB-PROD-01
Process:        rundll32.exe → accessing lsass.exe
User:           svc_remoteaccess04
Technique:      T1003.001 OS Credential Dumping: LSASS Memory
EDR action:     ALERT ONLY not blocked (monitor mode)
Command:        rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 624 C:\Windows\Temp\svchost.dmp full
File created:   C:\Windows\Temp\svchost.dmp (38 MB)
Active session: Same origin CTX-8847FA02
```

**My triage reasoning:**

The attacker has moved from the Citrix host into DB-PROD-01 one of the database servers identified during the SMB sweep 22 minutes ago. This is lateral movement confirmed. They are no longer contained to the entry point.

The command is unambiguous: `comsvcs.dll MiniDump` targeting LSASS process ID 624. This is one of the most documented credential dumping techniques in existence, mapped explicitly at MITRE T1003.001. The purpose is to read LSASS memory and extract NTLM password hashes and Kerberos tickets for every account that has authenticated on this machine. With those hashes, the attacker does not need cleartext passwords they can authenticate as any of those users directly using Pass-the-Hash techniques, effectively becoming those users in the eyes of every system on the domain.

The 38MB dump file is still on disk. It has not been exfiltrated yet. This is the last moment where intervention can prevent the attacker from expanding their access to every account whose credentials were cached on this server.

The EDR alert in monitor mode is the critical failure here. The technology detected the attack. The configuration choice not to block it automatically turned a detection capability into a documentation capability.

**Decision:** This is a Priority 1 incident. The attacker is now inside a production database server, has extracted credentials from memory, and the session that opened this intrusion is still active. War room must be activated immediately. Isolate DB-PROD-01 from the network if authorized. Delete or quarantine the dump file before it leaves the host. Reset credentials for all accounts that had sessions on DB-PROD-01.

**MITRE ATT&CK:**
- T1003.001 OS Credential Dumping: LSASS Memory
- T1218.011 System Binary Proxy Execution: Rundll32
- T1550.002 Use Alternate Authentication Material: Pass the Hash

---

### Alert 4 | February 15, 2024 | 22:47 EST

```
RULE:    DATA_EXFIL_VOLUME_THRESHOLD_012
SOURCE:  netflow, proxy_logs, dlp_sensor
LEVEL:   CRITICAL

Origin:           DB-PROD-01 / DB-PROD-03
Destination:      185.220.101.89 bulletproof hosting
Volume:           847 GB in last 6h (cumulative: ~2.1 TB)
Protocol:         HTTPS port 443 encrypted
Tool detected:    rclone.exe renamed to svchost32.exe
Daily baseline:   ~12 GB outbound/day
DLP trigger:      PHI keywords SSN, DOB, ICD-10, insurance_member_id
Account:          svc_remoteaccess04
Days since entry: 3 session never terminated
```

**My triage reasoning:**

Three days have passed since the initial login alert. The session was never terminated. This is the direct consequence of uncontained access: the attacker has had 72 hours to escalate privileges, identify high-value data stores, stage the exfiltration, and begin the transfer.

The volume is 70 times above the daily baseline for these servers. 847GB in six hours to an external destination is not a number that requires sophisticated analysis to recognize as abnormal. It is the kind of anomaly that volume-based thresholds should catch immediately and this alert confirms they did catch it, three days too late.

The tool is rclone a legitimate cloud synchronization utility renamed to `svchost32.exe` to blend in with Windows system process names during a cursory review. This is a naming evasion technique targeting analysts who filter by process name without verifying the binary hash or digital signature. `svchost32.exe` is not a real Windows binary. The legitimate `svchost.exe` never has a number appended to it. Verifying the hash of this file against known-good Windows hashes would immediately expose it as an impostor.

The DLP sensor detected PHI keywords in the outbound stream Social Security numbers, dates of birth, ICD-10 diagnostic codes, insurance member IDs. This is structured healthcare data belonging to patients. It is leaving the network in encrypted form, which limits the DLP's ability to inspect and block it, but the volume and destination alone are sufficient grounds for immediate containment.

**Decision:** Block outbound traffic to 185.220.101.89 at the firewall immediately. Isolate DB-PROD-01 and DB-PROD-03 from all network segments. Engage legal and compliance teams HIPAA breach notification obligations are triggered from the moment PHI exposure is confirmed. Begin forensic preservation of all affected hosts before any system is shut down.

**MITRE ATT&CK:**
- T1048.002 Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- T1036.005 Masquerading: Match Legitimate Name or Location
- T1567 Exfiltration Over Web Service

---

### Alert 5 | February 21, 2024 | 02:58 EST

```
RULE:    MASS_FILE_ENCRYPTION_019
SOURCE:  edr_telemetry, file_integrity_monitor
LEVEL:   CRITICAL MASS EVENT

Hosts affected:      67 actively growing
Files encrypted:     400,000+ in 11 minutes
Extension:           .alphv BlackCat/ALPHV signature
Malware:             encryptor.exe (stolen digital certificate)
Propagation:         GPO modified deployed via Group Policy
Shadow copies:       DELETED vssadmin delete shadows /all /quiet
Recovery mode:       DISABLED bcdedit /set {default} recoveryenabled No
Ransom note:         ALPHV_README.txt created in all directories
Critical systems:    claims-proc-01, pharmacy-api-02, auth-srv-01 offline
Days since entry:    9 original session CTX-8847FA02 never terminated
```

**My triage reasoning:**

This is the point of no return. Nine days after the initial login alert went uncontained, the ransomware payload has been activated across the environment simultaneously.

The propagation mechanism deserves particular attention. The attacker used Group Policy Objects the Active Directory feature used by IT administrators to push software and configuration changes across the entire domain to deploy `encryptor.exe` to every machine in the domain at once. This was only possible because, at some point during the preceding nine days, the attacker escalated to Domain Admin privileges, almost certainly using credentials extracted during the LSASS dump in Alert 3. They did not need to compromise each machine individually. They used the organization's own administrative infrastructure to do it for them.

The deletion of Volume Shadow Copies and the disabling of recovery mode via `bcdedit` are deliberate anti-recovery steps executed before or alongside encryption. This removes the primary local recovery option Windows' own backup snapshots making it impossible to restore files without either paying the ransom or restoring from offline backups.

At this stage, the incident response is no longer about containment of the attacker. The attacker has executed and will not stop encryption mid-operation. The priorities now shift to: limiting further spread to unaffected network segments, preserving forensic evidence before systems are shut down, assessing the state of offline backups, and activating business continuity procedures.

**Decision:** Activate full incident response protocol. Contact CISO, legal counsel, and executive leadership immediately. Engage law enforcement FBI Cyber Division for ransomware of this scale and impact. Begin network isolation of affected segments to protect any systems not yet reached by the GPO deployment. Do not shut down affected systems before forensic memory capture. Begin assessment of offline backup integrity.

**MITRE ATT&CK:**
- T1486 Data Encrypted for Impact
- T1490 Inhibit System Recovery
- T1484.001 Domain Policy Modification: Group Policy Modification
- T1078.002 Valid Accounts: Domain Accounts

---

### Alert 6 | February 21, 2024 | 03:12 EST

```
RULE:    C2_BEACON_PERIODIC_023
SOURCE:  netflow, proxy_logs, dns_logs
LEVEL:   CRITICAL

Host:           CITRIX-HOST-07 (original entry point)
C2 destination: alphvmmm6sooxzm5.onion via Tor relay
Beacon interval: Every 4 minutes active since February 12
Protocol:       HTTPS over Tor fully encrypted
Process:        tor.exe renamed to winupdate32.exe
Persistence:    HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Running as:     SYSTEM
Active since:   2024-02-12 03:52 EST 9 minutes after initial login
```

**My triage reasoning:**

This alert reveals that the C2 channel was established nine minutes after the initial Citrix login at 03:52 on February 12 and has been beaconing every four minutes for nine days without detection.

The implication is significant: the attacker had command and control infrastructure active throughout the entire attack chain. Every lateral movement decision, every tool deployment, every exfiltration operation was potentially coordinated through this channel. The .onion destination routes through Tor, making it practically impossible to trace back to the attacker's actual infrastructure.

The persistence mechanism is a standard Windows Run registry key `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` pointing to `winupdate32.exe`. This binary is `tor.exe` renamed to impersonate a Windows update process. It runs as SYSTEM, meaning it has the highest privilege level on the host. It survives reboots. Simply terminating the process without removing the registry key and deleting the binary would result in the C2 channel restarting on the next reboot.

The nine-day beacon interval that went undetected reflects a gap in network monitoring at this environment: either .onion traffic was not being flagged, DNS-over-HTTPS queries were not being inspected, or the beacon pattern was simply below the detection threshold set for outbound connections. Any of these would need to be addressed as part of post-incident remediation.

**Decision:** Preserve the full beacon log for law enforcement timestamps, byte counts, and any detectable payload patterns are valuable for the FBI investigation. Remove the persistence key and binary from CITRIX-HOST-07 after forensic imaging. Block all Tor-related traffic at the perimeter. Conduct a full sweep of the environment for similar Run key entries and renamed binaries.

**MITRE ATT&CK:**
- T1071.001 Application Layer Protocol: Web Protocols
- T1090.003 Proxy: Multi-hop Proxy (Tor)
- T1547.001 Boot or Logon Autostart Execution: Registry Run Keys
- T1036.005 Masquerading: Match Legitimate Name or Location

---

## What the Real SOC Missed and Why

Every one of the six alerts above was generated by tools that were operational. The SIEM fired. The EDR fired. The DLP fired. The network IDS fired. None of them failed to detect. What failed was the response.

The EDR was running in monitor mode configured to alert without blocking which is a common operational decision in environments where aggressive blocking generates too many false positives and interrupts legitimate business operations. The result in this case was that a detected LSASS dump was documented but not stopped.

The DLP had the same configuration problem. It detected PHI leaving the network. It alerted. It did not block.

The initial alert a login from a Tor exit node to an account with no MFA, at 03:47 AM, from a geolocation that did not match the user's profile did not trigger an automatic response. In a 24/7 SOC environment with clear escalation procedures, a human analyst receiving this alert should have escalated within minutes. Whether the alert was seen, deprioritized, or simply not acted upon quickly enough is a process failure, not a technology failure.

The nine-day dwell time between initial access and ransomware deployment was not stealth. The attacker generated multiple high and critical severity alerts across that window. The chain was visible in the SIEM. What was missing was the correlation the habit of asking whether any of today's alerts are connected to something from yesterday, or last week, and what story they tell together.

---

## Key Lessons for SOC Analysts

**1. Sessions are not passive.** An active session from an anomalous login is not a ticket to investigate later. It is an open door with someone walking through it right now. The calculus on false positives changes completely when the threat is live.

**2. Monitor mode is not detection.** EDR and DLP configured to alert without acting are logging tools, not security controls. Their value depends entirely on the speed and quality of human response. If that response is slow or absent, monitor mode provides no protection only documentation of the breach after the fact.

**3. Credential dumping is a pivoting event, not an endpoint event.** When LSASS is dumped on one machine, the attacker's reach immediately expands to every account whose credentials were cached there. The response cannot be limited to the machine where the dump happened. Every account on that machine must be treated as compromised.

**4. Tool renaming is trivial evasion.** `svchost32.exe` and `winupdate32.exe` are not Windows binaries. Any analyst or automated tool that checks process names against a known-good list would catch this immediately. Hash verification and digital signature inspection should be standard practice before trusting a process name.

**5. MFA on remote access is not optional.** The entire nine-day intrusion, the 6TB exfiltration, the $22 million ransom payment, and the disruption of healthcare services for 190 million Americans originated from a single credential used on a portal without MFA. One control. One missing configuration. That is the full scope of what enabled this attack.

**6. Dwell time is the attacker's most valuable resource.** The Change Healthcare attacker had nine days. In nine days they mapped the network, escalated privileges, exfiltrated the data, established persistent C2, and staged the ransomware. Every hour of uncontained access in the early stages compounds exponentially. The correct response to Alert 1 would have prevented every alert that followed.

---

## References

- UnitedHealth Group CEO Andrew Witty Congressional Testimony (May 2024): https://www.finance.senate.gov/hearings/hacking-america-s-health-care-examining-the-change-healthcare-cyber-attack-and-what-s-next
- HHS OCR Breach Portal Change Healthcare: https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
- CISA / HHS ALPHV/BlackCat Advisory (AA23-353A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a
- MITRE ATT&CK ALPHV/BlackCat: https://attack.mitre.org/software/S1068/
- American Hospital Association Change Healthcare Impact Report: https://www.aha.org/change-healthcare-cyberattack-underscores-urgent-need-strengthen-cyber-preparedness-individual-health-care-organizations-and

---

*This analysis was conducted as an independent case study exercise, reconstructing real alert data from publicly available incident reports, congressional testimony, and post-incident forensic disclosures to develop and demonstrate SOC analyst triage reasoning.*
