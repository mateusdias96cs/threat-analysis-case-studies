# Threat Analysis: Uber Security Breach (2022)
### SOC Analyst Perspective: Alert Triage and Incident Reasoning

**Analyst:** Mateus Dias  
**Analysis Date:** 2026-05-15  
**Case Type:** Real-world incident case study, triage simulation  
**Incident Date:** September 15, 2022  
**Discovery:** September 15, 2022 (same day)  
**Threat Actor:** Lapsus$ (attributed)  

---

## Preface

This document reconstructs the Uber 2022 security breach from the perspective of a SOC analyst receiving alerts in real time. The goal is to document the triage reasoning applied to each alert as it appeared, identify the decisions that contained or failed to contain the attack, and extract lessons for modern SOC operations.

The alerts below are based on publicly documented indicators from the Uber breach investigation. The triage reasoning is my own, applied sequentially as each alert arrived.

---

## Incident Background

On September 15, 2022, an 18-year-old attacker compromised Uber's internal systems using a combination of stolen credentials, MFA fatigue, and social engineering via Slack. The attacker gained access to AWS production, Google Cloud admin, GitHub source code repositories, internal finance tools, and most critically, HackerOne internal bug bounty reports containing undisclosed vulnerabilities.

The attack relied almost entirely on human factors rather than technical exploits, making it a benchmark case for understanding social engineering at enterprise scale.

---

## Alert Timeline and Triage Reasoning

---

### Alert 1 | 22:17:03 | September 15, 2022

```
Level: LOW
Event: MFA push notification sent
User: contractor_account@uber.com
Device: iPhone - Sao Paulo, Brazil
Destination: Okta Verify
Frequency: 1x
Status: No response
```

**My triage reasoning:**

A single MFA push with no response is one of the most common events in any corporate environment. Users receive push notifications regularly when they attempt to log in, mistype a password, or are prompted for re-authentication. One unanswered notification carries no meaningful signal on its own.

With exclusively this information available, there is no actionable indicator. The correct decision is to close the ticket and continue monitoring the queue.

**Decision:** Close. No action required.

**MITRE ATT&CK:** T1621 - Multi-Factor Authentication Request Generation (not yet confirmed at this stage)

---

### Alert 2 | 22:34:17 | September 15, 2022

```
Level: LOW
Event: MFA push notification sent
User: contractor_account@uber.com
Device: iPhone - Sao Paulo, Brazil
Destination: Okta Verify
Frequency: 8x in 17 minutes
Status: All ignored
```

**My triage reasoning:**

The volume changed everything. Eight push notifications in 17 minutes from the same account is no longer ambient noise, but it is not yet confirmation of an attack. There are two plausible explanations at this point.

The first is benign: the user forgot their password and is repeatedly attempting to log in, triggering repeated MFA pushes without realizing they need to reset their credentials first. Eight attempts over 17 minutes is within the range of a frustrated legitimate user.

The second is malicious: an attacker with stolen credentials is deliberately flooding the user with MFA notifications hoping they accept one out of fatigue or confusion. This technique is called **MFA Fatigue** and it is specifically designed to look like user error.

Before taking any action, I would check the support ticketing system to verify whether this user submitted a password reset request or contacted the helpdesk. If a support ticket exists, this is likely benign. If no ticket exists and the account has no recent helpdesk activity, the malicious explanation becomes significantly more probable.

Closing the ticket without this verification would be the error. The correct posture is to hold the ticket open, check for support context, and monitor for the next event.

**Decision:** Do not close. Check support ticket history. Monitor actively.

**MITRE ATT&CK:** T1621 - Multi-Factor Authentication Request Generation

---

### Alert 3 | 22:51:44 | September 15, 2022

```
Level: MEDIUM
Event: MFA push accepted
User: contractor_account@uber.com
Device: iPhone - Sao Paulo, Brazil
Location of acceptance: Sao Paulo, Brazil
Login origin IP: 195.2.253.142
IP geolocation: Ukraine
Status: Authentication successful
```

**My triage reasoning:**

Because I kept Alert 2 open and was actively monitoring, I now have the complete picture to present when escalating. This is why not closing Alert 2 was the critical decision.

The geographic impossibility here is the clearest indicator of account compromise I could receive. The MFA was accepted on a device physically located in Brazil. The login request originated from an IP in Ukraine. These two events cannot be produced by the same legitimate user simultaneously. This is a textbook **Account Takeover (ATO)** signature.

What happened is now clear: an attacker in Ukraine obtained the contractor's credentials through unknown means, then flooded the user with MFA notifications until the user accepted one, likely out of fatigue or confusion.

I would escalate immediately to Tier 2 with the full context: Alert 1 (single ignored push, closed), Alert 2 (eight ignored pushes in 17 minutes, held open for monitoring), Alert 3 (push accepted, Ukraine IP origin confirmed). The narrative is complete and the escalation path is fully documented.

**Decision:** Escalate immediately to Tier 2. Present the three-alert chain. This is an active account compromise.

**MITRE ATT&CK:**
- T1621 - Multi-Factor Authentication Request Generation
- T1078 - Valid Accounts
- T1556 - Modify Authentication Process

---

### Alert 4 | 23:02:11 | September 15, 2022

```
Level: LOW
Event: Slack direct message
Sender: contractor_account@uber.com
Recipient: internal_engineer@uber.com
Message: "Hi, I'm from Uber IT support.
We detected suspicious activity on your
network segment. I need you to confirm
your access credentials for verification."
```

**My triage reasoning:**

Arriving simultaneously with the escalation of Alert 3, this message confirmed that the attacker was already moving laterally inside the environment using the compromised account.

Three attack techniques are present in this single message. The first is **social engineering**: creating a false sense of urgency by claiming suspicious activity was detected. The second is **impersonation**: pretending to be Uber IT support using an internal account, which gives the message significant perceived legitimacy compared to an external email. The third is **pretexting**: constructing a plausible scenario to justify an unusual request.

No legitimate IT support team at an enterprise of Uber's scale would request credentials through a direct message on Slack. This violates basic security policy. The request is fraudulent regardless of who appears to be sending it.

My immediate action would be to contact the recipient engineer directly by phone, not by Slack or email, since those channels may be monitored or compromised. I would instruct them not to respond, not to provide any information, and to log out of any active sessions if they have already interacted with the message. This is out-of-band verification applied to protect the victim before further damage occurs.

**Decision:** Contact the recipient immediately by phone. Do not respond through Slack. Flag the compromised account for suspension pending investigation.

**MITRE ATT&CK:**
- T1534 - Internal Spearphishing
- T1656 - Impersonation
- T1566 - Phishing

---

### Alert 5 | 23:08:33 | September 15, 2022

```
Level: CRITICAL
Event: Privileged access detected
User: contractor_account@uber.com
Systems accessed:
  - AWS production environment
  - Google Cloud admin panel
  - HackerOne bug bounty platform (internal reports)
  - GitHub source code repositories
  - Uber internal finance tools
Access type: Admin level
Duration: 6 minutes active
```

**My triage reasoning:**

Six minutes of admin-level access across production infrastructure, source code, financial tools, and most critically, HackerOne internal reports.

The HackerOne access deserves specific attention because it is not immediately obvious to everyone why it is catastrophic. HackerOne internal reports contain vulnerability disclosures submitted by external security researchers that have not yet been patched. The attacker now has a complete map of Uber's known but unresolved security weaknesses. This information can be used to plan a second attack exploiting those vulnerabilities, or sold on darkweb markets where it commands significant value precisely because the vulnerabilities are still open. This is qualitatively different from accessing generic internal data.

Combined with source code access and production environment credentials, the attacker has the capability to cause sustained damage long after this session ends. Every second of continued access exponentially increases the potential impact.

This is no longer a triage situation. This is an active critical incident.

My immediate actions in the next five minutes: request war room activation, escalate directly to CISO given the scope of systems involved, initiate suspension of the compromised account and revocation of all active sessions, begin damage assessment to determine exactly which data was accessed or exfiltrated during the six-minute window, and preserve all logs for forensic investigation.

The CISO must be informed because this incident has executive, legal, and regulatory implications. A breach involving financial tools, source code, and production infrastructure at this scale requires decisions that go beyond the SOC chain of command.

**Decision:** War room activation. CISO notification. Account suspension. Immediate damage assessment. Incident response team activation.

**MITRE ATT&CK:**
- T1078.004 - Valid Accounts: Cloud Accounts
- T1530 - Data from Cloud Storage
- T1213 - Data from Information Repositories
- T1552 - Unsecured Credentials

---

## What the Real SOC Missed and Why

The Uber breach is unusual in that the SOC did eventually detect and respond to the attack on the same day it occurred. However, the critical failure was in the gap between Alert 2 and Alert 3.

The real analysts saw the MFA fatigue pattern and did not escalate or contact the user before the push was accepted. Those 17 minutes between the first and last push notification were the intervention window. Reaching out to the contractor directly during that window, by phone, to ask whether they were attempting to log in, would have confirmed the attack before access was granted.

The social engineering element also succeeded because Slack messages from internal accounts carry implicit trust. The assumption that internal communications are safe is one of the most exploited gaps in enterprise security.

---

## Key Lessons for SOC Analysts

**1. MFA fatigue is an attack, not user error.**
Repeated unanswered MFA pushes in a short window is not a technical failure. It is a deliberate technique. Treat high-frequency MFA activity from the same account as a potential attack in progress, not a helpdesk case.

**2. The intervention window is between the pushes, not after acceptance.**
Once MFA is accepted from an impossible geographic location, the attacker is already inside. The time to act is during the push flood, before the user accepts. Contacting the user out-of-band during this window is the correct response.

**3. Internal messages do not equal trusted messages.**
A compromised internal account sends internal messages. The source appearing legitimate does not make the content legitimate. Requests for credentials through any channel, from any sender, are automatically suspicious.

**4. HackerOne access is not just a data breach, it is a vulnerability map.**
Access to internal bug bounty reports gives an attacker a prioritized list of open vulnerabilities in the target's own systems. This is qualitatively different from accessing generic internal data and should be treated as a critical finding with immediate patching implications.

**5. Time is the most important variable in a live incident.**
Six minutes of admin access across production systems represents massive potential damage. Every minute of delayed response after confirming an active compromise directly increases the blast radius. War room activation and CISO notification are not bureaucratic steps, they are time-critical actions.

---

## Incident Summary

| Field | Value |
|-------|-------|
| Attack vector | Stolen credentials plus MFA fatigue |
| Initial access | Contractor account via Okta |
| Lateral movement | Internal Slack impersonation |
| Systems compromised | AWS, Google Cloud, GitHub, HackerOne, Finance |
| Most critical access | HackerOne internal vulnerability reports |
| Detection | Same day, SOC alert correlation |
| Threat actor | Lapsus$ (attributed) |
| Root cause | No MFA fatigue detection rule, implicit trust in internal Slack |

---

## References

- Uber Security Update (September 2022): https://www.uber.com/newsroom/security-update
- MITRE ATT&CK - Lapsus$: https://attack.mitre.org/groups/G1004/
- T1621 - MFA Request Generation: https://attack.mitre.org/techniques/T1621/
- T1534 - Internal Spearphishing: https://attack.mitre.org/techniques/T1534/

---

*This analysis was conducted as an independent case study exercise, reconstructing real alert data from publicly available incident reports to develop and demonstrate SOC analyst triage reasoning.*
