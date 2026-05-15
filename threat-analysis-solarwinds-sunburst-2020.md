# Threat Analysis: Operation Sunburst (SolarWinds 2020)
### SOC Analyst Perspective: Alert Triage and Incident Reasoning

**Analyst:** Mateus Dias  
**Analysis Date:** 2026-05-15  
**Case Type:** Real-world incident case study, triage simulation  
**Incident Period:** March to December 2020  
**Discovery:** December 13, 2020 (FireEye)  

---

## Preface

This document reconstructs the SolarWinds Sunburst attack from the perspective of a SOC analyst receiving alerts in real time, before the incident was publicly known. The goal is to document the triage reasoning applied to each alert as it appeared, identify the detection opportunities that were missed, and extract lessons applicable to modern SOC operations.

The alerts below are based on publicly documented indicators from the Sunburst investigation. The triage reasoning is my own, applied without prior knowledge of the outcome.

---

## Incident Background

In early 2020, threat actors (later attributed to APT29/Cozy Bear) compromised the SolarWinds software build pipeline and inserted a backdoor codenamed **Sunburst** into the legitimate Orion software update **2019.4.5200.9083**. This update was distributed to approximately 18,000 organizations worldwide, including U.S. federal agencies, Fortune 500 companies, and critical infrastructure operators.

The malware remained dormant for 12 to 14 days after installation before beginning C2 communication, a deliberate evasion technique to avoid sandbox detection environments that typically run for shorter periods.

---

## Alert Timeline and Triage Reasoning

---

### Alert 1 | March 12, 2020 | 08:43

```
Level: LOW
Process: solarwinds.businesslayerhost.exe
Event: Outbound DNS query
Destination: r1qc2mmgufta4o9s.appsync-api.us-east-1.avsvmcloud.com
Frequency: 1x
```

**My triage reasoning:**

The first thing that caught my attention was the subdomain structure: `r1qc2mmgufta4o9s`. This is a 16-character random string with no semantic meaning. No legitimate software generates subdomains like this. Standard software update endpoints use human-readable paths like `updates.vendor.com` or `api.vendor.com/v2/check`. A randomized string of this pattern is a strong indicator of **Domain Generation Algorithm (DGA)**, a technique used by malware to generate C2 destinations dynamically and avoid static blocklists.

My immediate action would be to query the domain on VirusTotal and check the registration date. A clean score (0/92) does not rule out malicious intent. Adversaries operating at this level register domains weeks in advance specifically to build a clean reputation before activating them.

The critical question before closing this ticket: *"Why does a network monitoring software need to query a subdomain with a randomly generated 16-character string?"* There is no legitimate answer to that question.

**Context consideration:** In a high-value asset environment such as a federal agency, financial institution, or Fortune 500 company, Zero Trust principles apply. A single anomalous DNS query from a trusted process is still an anomaly worth documenting. In a small or medium business with limited threat exposure, this might reasonably be deprioritized given resource constraints. Context of the protected asset must always inform triage decisions.

**Decision:** Flag for monitoring. Document the subdomain pattern. Do not close.

**MITRE ATT&CK:** T1071.004 - Application Layer Protocol: DNS

---

### Alert 2 | March 26, 2020 | 14:18

```
Level: LOW
Process: solarwinds.businesslayerhost.exe
Event: Outbound HTTP GET
Destination: 20.140.0.1 (Microsoft Azure)
User-Agent: SolarWinds (compatible)
Data transferred: 12KB
Frequency: 3x same day
```

**My triage reasoning:**

On the surface this looks legitimate: Microsoft Azure IP, SolarWinds User-Agent, signed process. But three details changed my assessment.

First, the **frequency**: three GET requests in a single day to the same destination is a polling pattern. Legitimate software updates happen once per session or on a defined schedule, not three times in one day. This is consistent with **beaconing behavior**, where malware checks its C2 at regular intervals for new commands. I had already seen this pattern in network traffic analysis. Repeated GET requests to the same endpoint at fixed intervals is one of the clearest C2 signatures.

Second, the **12KB outbound transfer**: small, seemingly harmless. But at this stage I am already asking what exactly is being sent. Software telemetry is typically inbound (receiving updates) not outbound (sending data).

Third, and most importantly, this is the **same process** that generated the suspicious DNS query 14 days ago. A pattern is forming.

The right question here is not whether this IP is legitimate. It is whether this behavior matches the documented behavior of the SolarWinds Orion product. That requires checking with the software vendor or internal documentation. No change ticket, no approval record for this communication means this ticket does not close.

**Decision:** Escalate. Correlate with Alert 1. Request change management verification.

**MITRE ATT&CK:** T1071.001 - Application Layer Protocol: Web Protocols

---

### Alert 3 | April 26, 2020 | 02:17

```
Level: MEDIUM
Event: New scheduled task created
Task name: SystemEvaluation
Executable: C:\Windows\SysWOW64\rundll32.exe
Arguments: /i /s
Created by: SYSTEM
Parent process: solarwinds.businesslayerhost.exe
Time: 02:17:03
```

**My triage reasoning:**

Three elements in this alert demand immediate attention when read together.

**Time of execution:** 02:17 AM. Legitimate scheduled maintenance tasks are documented, approved, and typically occur during defined maintenance windows. An unscheduled task created in the early hours of the morning with no corresponding change ticket is a significant anomaly.

**The parent process:** `solarwinds.businesslayerhost.exe` again. This is now the third alert involving the same process in 45 days. At this point the process itself is suspicious, regardless of its legitimate signature. A digitally signed process can still be exploited or serve as a loader for malicious activity.

**The technique:** `rundll32.exe` with generic arguments is a textbook **Living off the Land (LotL)** technique. It uses legitimate Windows binaries to execute malicious code in order to evade detection tools that whitelist system executables. Attackers use this specifically because it blends into normal Windows activity.

Reading this alert in isolation might seem borderline. Reading it as the third event from the same suspicious process, after anomalous DNS queries and unexplained outbound transfers, this is no longer borderline.

**Decision:** Escalate immediately to Tier 2. Present the full chain: Alert 1 (DGA DNS query), Alert 2 (beaconing pattern, outbound data), Alert 3 (persistence via LotL at 2AM). The story these three alerts tell together is not noise.

**MITRE ATT&CK:**
- T1053.005 - Scheduled Task/Job
- T1218.011 - System Binary Proxy Execution: Rundll32

---

### Alert 4 | June 9, 2020 | 16:51

```
Level: MEDIUM
Event: Privileged account created
Account: svc_monitoring_adfs
Privileges: Domain Admin
Created by: SYSTEM
Source process: solarwinds.businesslayerhost.exe
```

**My triage reasoning:**

A Domain Admin account created by the SYSTEM account via the SolarWinds process is a critical finding. Domain Admin is the highest privilege level in a Windows Active Directory environment. Whoever controls this account controls the entire domain.

The infrastructure team responded by email saying it was intentional, that a new Orion module required it. This is where I would not accept the email at face value.

My reasoning: an attacker who has been inside the environment for over 90 days at this point has had time to study internal communication patterns, team schedules, ongoing projects, and planned changes. The timing of this account creation correlating with a legitimate infrastructure activity is not necessarily a coincidence. It could be a deliberate synchronization. The attacker monitors internal communications, identifies a legitimate upcoming change, and executes the malicious action within the same window to blend in.

This technique, timing malicious actions to coincide with legitimate business activity, is one of the most sophisticated evasion methods used by advanced persistent threats.

**Out-of-band verification is mandatory here.** I would not accept an email response as confirmation. I would contact the infrastructure team lead directly by phone or in person and ask three specific questions:
1. Is there a change ticket for this account creation?
2. Which specific Orion module requires Domain Admin privileges?
3. Was this change scheduled and approved through the change management process?

If any answer is "no" or "I don't know", this is an active incident.

**Decision:** Do not close. Mandatory out-of-band verification. If unconfirmed within 30 minutes, treat as active compromise and escalate to incident response.

**MITRE ATT&CK:**
- T1078 - Valid Accounts
- T1136 - Create Account
- T1484 - Domain Policy Modification

---

### Alert 5 | July 10, 2020 | 11:19

```
Level: LOW
Process: solarwinds.businesslayerhost.exe
Event: Outbound HTTPS connection
Destination: databasegalore.com
Data transferred: 47KB outbound
Duration: 4 minutes
Previous alerts from same process: 4 in the last 120 days
```

**My triage reasoning:**

At this point, if escalation had not already occurred, this alert alone would force the conversation.

47KB of outbound data to an external domain is data leaving the organization. The destination name `databasegalore.com` has no documented relationship to SolarWinds or any internal system. VirusTotal returning 0/92 means nothing at this stage. The entire Sunburst operation was built on infrastructure that was clean on reputation services. Clean reputation is a precondition for this class of attack, not evidence of legitimacy.

The detail that confirms the pattern: **"Previous alerts from same process: 4 in the last 120 days."** This is not a new event. This is the fifth data point in a chain. Each individual event was small, quiet, and seemingly explainable. Together they describe a classic **low and slow exfiltration** strategy.

The attacker's logic is precise. Large data transfers trigger volume-based alerts. Frequent transfers trigger frequency-based alerts. But 47KB once a month, from a trusted and signed process, to a clean domain, during business hours, is designed to stay below every threshold while still accomplishing the objective.

**Decision:** This is no longer a triage decision. This is an active incident. Immediate escalation to Tier 2 and incident response. Present the complete 120-day alert chain to leadership. Recommend war room activation for containment and damage assessment, mapping exactly what data left the organization, what systems were accessed, and what credentials may be compromised.

**MITRE ATT&CK:**
- T1041 - Exfiltration Over C2 Channel
- T1567 - Exfiltration Over Web Service

---

## What the Real SOC Missed and Why

The real analysts closed every one of these alerts. Not because they were incompetent, but because each alert, viewed in isolation, had a plausible innocent explanation.

The failure was not correlating across time. The SIEM had all five data points. The information was there. What was missing was the habit of asking: *"Have I seen this process before? What is the story these alerts tell together?"*

The Sunburst attack was discovered in December 2020, not by the organizations' SOC teams, but by FireEye, who noticed an anomalous MFA registration for one of their own employee accounts. Nine months after the initial compromise.

---

## Key Lessons for SOC Analysts

**1. Process reputation does not equal process behavior.**
A digitally signed, legitimate process can be exploited or used as a loader. Always question what a process is doing, not just what it is.

**2. VirusTotal clean does not mean safe.**
Advanced adversaries pre-register infrastructure specifically to build clean reputations. A 0/92 score on a domain with a random subdomain string is not reassurance. It is expected.

**3. Alert correlation across time is the most critical skill.**
Each of the five alerts above was explainable in isolation. Together they described a full attack chain: initial access, C2 establishment, persistence, privilege escalation, exfiltration. The chain was visible. It just required connecting the dots.

**4. Out-of-band verification is non-negotiable for privileged actions.**
When a privileged account is created and a team says it was them, verify through a different channel. Email can be compromised. Phone calls and in-person confirmation cannot be spoofed at the same scale.

**5. Low and slow is the hardest attack to detect.**
Volume-based and frequency-based thresholds are designed for noisy attacks. Patient adversaries stay below every threshold deliberately. The counter is behavioral baselines: knowing what normal looks like and flagging deviations, not just volume spikes.

---

## References

- FireEye Sunburst Analysis: https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- CISA Alert AA20-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- MITRE ATT&CK - APT29: https://attack.mitre.org/groups/G0016/
- Microsoft Sunburst Technical Analysis: https://aka.ms/solorigate

---

*This analysis was conducted as an independent case study exercise, reconstructing real alert data from publicly available incident reports to develop and demonstrate SOC analyst triage reasoning.*
