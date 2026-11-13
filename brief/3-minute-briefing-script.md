# 3-Minute Executive Briefing Script

**Context:** This script was designed for a verbal briefing to the CISO and Finance leadership to escalate the incident to P1. It focuses on the bottom line, the business impact, and immediate containment recommendations, while being transparent about evidence gaps. 

---

**Morning. Bottom line: confirmed compromise of a Finance account, and the attacker is still active. I recommend escalating as P1. All times are West Africa Time.**

**What happened.** At 08:40 a phishing email arrived: a fake DHL invoice. SPF failed, DKIM was absent and DMARC failed, but the sender's policy is p=none, so it was delivered anyway. The visible link said dhl.com; the real link pointed to dhl-invoices-ng.example. 

At 08:50 Ngozi's Outlook saved the attached macro workbook and Excel opened it. Hidden PowerShell then downloaded a script from 203.0.113.45, the same server the email infrastructure points to. Within 81 seconds of the attachment being saved, a scheduled task called OneDriveSyncHelper was registered to run every 15 minutes. EDR flagged it at 08:52 as Medium. Nobody actioned it.

The packet capture shows a second mechanism. From 08:52 the laptop called out to 198.51.100.77 every 60 seconds, 14 check-ins. That beacon began 14 minutes before the task first ran, so it is not the scheduled task. 

At 09:00, 14 failed VPN logins came from an IP tagged Romania, and the next attempt succeeded, because her account sits on a legacy profile that does not require MFA. At 09:09 the same IP read her mailbox over legacy IMAP: 212 items. At 09:12 it read supplier bank details, vendor payments and payroll from the Finance share. At 09:15 it created an inbox rule forwarding invoice and payment mail to accounts.dhl.ng at mail-secure-pay.example and deleting the originals. **That address is exactly the Reply-To on the phishing email.** It links the email to the cloud compromise.

**Confidence and gaps.** I am highly confident in the endpoint chain, the MFA bypass, the share access and the email-to-cloud link, because six sources line up closely. I will not claim three things. I cannot prove data left, although the VPN sent about 47 megabytes to the client. There is no evidence she clicked the link; the only contact with the lookalike domain is the macro's own fetch. And the retrieved script is a 94-byte placeholder that cannot beacon or create a task, so I cannot name it as the implant. That is an inconsistency in the evidence pack, and I am flagging it, not hiding it.

**Recommendations, all needing approval.** 
One: revoke all sessions and refresh tokens. We reset the password at 09:40, yet the attacker's token worked at 09:58 and they read mail again at 10:14, so the reset did not evict them. 
Two: delete the inbox rule and block that address. 
Three: contain the laptop through EDR, capture memory, then remove the task. 
Four: block the three IPs and both domains. 
Five: hold all supplier payment and bank-detail changes until verified by phone. 
Six: enforce MFA on the VPN and block legacy authentication.

**That is my assessment. I am ready for questions.**
