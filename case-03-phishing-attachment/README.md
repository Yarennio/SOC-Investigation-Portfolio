# Phishing Attachment Investigation

> [!NOTE]
> **Lab Context:** This investigation was conducted in a TryHackMe simulated SOC environment. All email addresses, domains, attachments, users, and other entities shown in this case belong to the lab environment.

## Scenario

A suspicious inbound email was identified containing an urgent overdue payment message and a ZIP attachment named `ImportantInvoice-February.zip`.

The email was sent from the external address `john@hatmakereurope.xyz` and used financial urgency, account suspension warnings, and legal pressure to encourage the recipient to open the attached archive.

Initial reputation and file analysis did not identify the sender domain or attachment as malicious. However, the email context and social engineering indicators required further investigation before the alert could be classified.

The case was investigated to determine whether the message represented legitimate business communication or a phishing attempt involving a suspicious attachment.

## Initial Alert

The initial alert reported a suspicious attachment within an inbound email.

The message was sent from:

`john@hatmakereurope.xyz`

to:

`michael.ascot@tryhatme.com`

The subject was:

`FINAL NOTICE: Overdue Payment - Account Suspension Imminent`

The message claimed that the recipient's account was 30 days past due and warned that the account would be suspended unless immediate payment was made.

It also threatened legal action if payment was not received within 24 hours and instructed the recipient to open the attached invoice:

`ImportantInvoice-February.zip`

The combination of an external sender, urgent financial language, legal pressure, and a compressed attachment required further investigation.

## Investigation

The investigation focused on the sender, the email content, and the attached ZIP file.

The inbound email originated from the external domain:

`hatmakereurope.xyz`

The message used several social engineering techniques to create urgency and pressure the recipient into opening the attachment, including:

- A claim that the account was 30 days overdue
- A warning that the account would be suspended
- A threat of legal action
- A 24-hour payment deadline
- An instruction to immediately open the attached invoice

The attachment was identified as:

`ImportantInvoice-February.zip`

The file was located in the lab environment and its SHA-256 hash was calculated for further analysis:

`145BB70ABD0CC625F4A7ADD8CFB08982C39C4573470C8B87DB41D755BD2F9EA0`

File analysis confirmed that the attachment was a ZIP archive and returned a `CLEAN` result.

The sender domain `hatmakereurope.xyz` was also checked using the available URL/IP reputation analysis tool and returned a `CLEAN` result.

However, these clean reputation results were not treated as proof that the message was benign.

The investigation therefore considered the complete context of the email, including:

- The external sender
- The urgent payment-related language
- The threat of account suspension
- The threat of legal action
- The short payment deadline
- The instruction to immediately open a ZIP attachment
- The use of a compressed archive in an unsolicited financial message

When reviewed together, these indicators remained consistent with a phishing and social engineering pattern despite the clean initial reputation results.

The alert was therefore not closed as a False Positive based solely on reputation data.

## Evidence

The following evidence supported the investigation:

- The email was received from the external sender `john@hatmakereurope.xyz`.
- The recipient was `michael.ascot@tryhatme.com`.
- The message was inbound.
- The subject used urgent financial language: `FINAL NOTICE: Overdue Payment - Account Suspension Imminent`.
- The email claimed that the recipient's account was 30 days overdue.
- The message threatened account suspension and legal action.
- The recipient was given a 24-hour payment deadline.
- The email instructed the recipient to immediately open `ImportantInvoice-February.zip`.
- The attachment was confirmed as a ZIP archive.
- The SHA-256 hash of the attachment was calculated as `145BB70ABD0CC625F4A7ADD8CFB08982C39C4573470C8B87DB41D755BD2F9EA0`.
- File analysis returned a `CLEAN` result.
- The sender domain `hatmakereurope.xyz` also returned a `CLEAN` reputation result.
- The clean scan results were treated as individual evidence points rather than proof that the message was legitimate.

### Evidence 1 – Suspicious Email and Attachment

<p align="center">
  <img
    width="651"
    height="384"
    alt="Suspicious overdue payment phishing email"
    src="https://github.com/user-attachments/assets/b79c0b84-c8d2-4ee8-ae11-4bcea5fcab09"
  />
</p>

<p align="center">
  <em>
    Figure 1 – The inbound email from <code>john@hatmakereurope.xyz</code> used urgent overdue-payment language, threatened account suspension and legal action, and included the ZIP attachment <code>ImportantInvoice-February.zip</code>.
  </em>
</p>

### Evidence 2 – Attachment Hash Verification

<p align="center">
  <img
    width="761"
    height="333"
    alt="PowerShell attachment hash verification"
    src="https://github.com/user-attachments/assets/125ba8e2-f162-44ea-8dee-c611c8b4e3b7"
  />
</p>

<p align="center">
  <em>
    Figure 2 – The ZIP attachment was located in the lab environment and its SHA-256 hash was calculated for further investigation.
  </em>
</p>

### Evidence 3 – File Analysis Result

<p align="center">
  <img
    width="587"
    height="643"
    alt="ZIP attachment file analysis"
    src="https://github.com/user-attachments/assets/e52d3248-3f9f-4470-b460-f3b993aad64f"
  />
</p>

<p align="center">
  <em>
    Figure 3 – File analysis identified <code>ImportantInvoice-February.zip</code> as a ZIP archive and returned a <code>CLEAN</code> result. The absence of a malicious detection was not treated as confirmation that the attachment was safe.
  </em>
</p>

### Evidence 4 – Sender Domain Reputation Check

<p align="center">
  <img
    width="642"
    height="746"
    alt="Sender domain reputation analysis"
    src="https://github.com/user-attachments/assets/31ccf248-c237-44be-91e5-03bca13c863d"
  />
</p>

<p align="center">
  <em>
    Figure 4 – The sender domain <code>hatmakereurope.xyz</code> returned a <code>CLEAN</code> result during URL/IP analysis. This result was considered alongside the email content and attachment rather than being used as a standalone verdict.
  </em>
</p>

## Indicators & Entities

- **Sender:** `john@hatmakereurope.xyz`
- **Sender Domain:** `hatmakereurope.xyz`
- **Recipient:** `michael.ascot@tryhatme.com`
- **Email Direction:** Inbound
- **Subject:** `FINAL NOTICE: Overdue Payment - Account Suspension Imminent`
- **Attachment:** `ImportantInvoice-February.zip`
- **Attachment Type:** ZIP Archive
- **SHA-256:** `145BB70ABD0CC625F4A7ADD8CFB08982C39C4573470C8B87DB41D755BD2F9EA0`
- **File Reputation Result:** `CLEAN`
- **Domain Reputation Result:** `CLEAN`
- **Activity Type:** Phishing / Social Engineering

## Attack Chain

The observed activity followed the sequence below:

`External Sender`  
→ Urgent overdue-payment email delivered to the recipient  
→ Account suspension and legal consequences were used to create pressure  
→ A 24-hour payment deadline increased the sense of urgency  
→ The recipient was instructed to immediately open `ImportantInvoice-February.zip`  
→ The attachment and sender domain were analyzed and returned `CLEAN` reputation results  
→ The complete email context remained consistent with phishing and social engineering behavior

The message relied primarily on urgency, financial pressure, and fear of consequences to influence the recipient into opening the attachment.

## Analysis

The email demonstrated several characteristics commonly associated with phishing and social engineering.

The sender used an external domain and delivered an unsolicited financial message containing a compressed attachment. The message attempted to create urgency by claiming that the recipient's account was 30 days overdue and would be suspended unless immediate payment was made.

The email also introduced additional pressure by threatening legal action and imposing a 24-hour deadline. The recipient was then instructed to immediately open the attached ZIP archive.

Both the attachment and sender domain returned `CLEAN` results during the available reputation checks. However, these results only represented individual analysis points and did not establish that the email itself was legitimate.

No evidence available in this investigation confirmed that the ZIP archive contained an executable or malicious payload.Therefore, the classification was not based on confirmed malware execution, but on the correlated phishing and social engineering indicators present in the email.

Instead, the assessment was based on the correlated email indicators, including the unsolicited financial context, urgent payment demand, legal pressure, external sender, and attached archive.

When reviewed together, the evidence was more consistent with a phishing and social engineering attempt than with normal business communication.

## Verdict

🟢 **True Positive**

The alert was classified as a True Positive because the overall email context and correlated indicators were consistent with a phishing attempt.

The message combined an external sender, an unsolicited overdue-payment claim, account suspension warnings, legal pressure, a short payment deadline, and an instruction to immediately open a ZIP attachment.

Although both the sender domain and attachment returned `CLEAN` reputation results, these results were not sufficient to override the suspicious behavioral and contextual indicators present in the email.

The case demonstrates that a clean reputation result should be treated as one piece of evidence rather than as a final determination of legitimacy.

> [!TIP]
> **Key Takeaway:** A clean domain or file reputation result does not automatically make an email benign. Phishing decisions should consider the full message context, social engineering techniques, sender information, attachment type, and other correlated evidence.

## Remediation

Recommended remediation actions include:

- Quarantine or remove the suspicious email from the recipient's mailbox.
- Prevent the recipient from opening or interacting with `ImportantInvoice-February.zip` until the attachment has been fully validated.
- Block or monitor the sender address `john@hatmakereurope.xyz` and the domain `hatmakereurope.xyz` if further investigation confirms unauthorized or malicious use.
- Search the email environment for additional messages from the same sender or domain.
- Identify whether other recipients received or interacted with similar messages.
- Review email gateway and endpoint telemetry for evidence of attachment access or subsequent suspicious activity.
- Investigate the recipient account and endpoint if there is evidence that the attachment was opened.
- Preserve relevant email headers, attachment hashes, and investigation findings for further analysis and incident correlation.
- Reinforce user awareness around urgent payment requests, legal threats, and unexpected compressed attachments.

## Lessons Learned

This investigation reinforced several important SOC and phishing-analysis principles:

- A `CLEAN` reputation result does not prove that an email, domain, or attachment is benign.
- Reputation services should be treated as supporting evidence rather than as the sole basis for an investigation decision.
- Social engineering techniques such as urgency, financial pressure, legal threats, and short deadlines are important phishing indicators.
- An external sender and compressed attachment become more significant when they appear together with suspicious message content.
- Analysts should distinguish between suspicious behavior and technically confirmed malware activity.
- A suspicious ZIP attachment should not automatically be described as malicious unless its contents or behavior provide evidence for that conclusion.
- Email investigations should correlate sender information, subject, message content, attachment characteristics, reputation data, and recipient context.
- Multiple weak indicators can become much more meaningful when they form a consistent behavioral pattern.
- True Positive classification can depend on the complete attack context rather than a single malicious detection.
