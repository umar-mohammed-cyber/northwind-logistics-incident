# Northwind Logistics Incident — End-to-End Investigation

**Role:** SOC Analyst (capstone) · **Date:** 27 Oct 2026 (simulated) · **Verdict:** Confirmed compromise — P1 major incident

A full-lifecycle incident investigation of a two-path compromise at a fictional logistics company: a macro-enabled phishing workbook on a Finance laptop, followed by an MFA-free VPN brute force, legacy IMAP mailbox access, and a matching inbox forwarding rule.

## Scenario
Northwind Logistics' Finance team received a fake "DHL" invoice. The macro dropped a scheduled task (`OneDriveSyncHelper`) for persistence, while a separate 60-second beacon called out to a hardcoded C2. The actor brute-forced the user's VPN account against a `legacy-staff` profile that did not require MFA, read the `Finance$` file share, then authenticated over legacy IMAP to the M365 mailbox and created an auto-deleting forwarding rule pointing at the phishing email's own Reply-To address.

**Key finding:** a password reset did not evict the attacker — a refresh token was reused, and the mailbox was read again later.

## Skills demonstrated
- **Incident Response:** Full NIST SP 800-61 lifecycle: detection → triage → scoping → containment recs → reporting
- **Log Analysis:** Windows Security (4624/4625/4698/4724/5140/5145), VPN, M365 unified audit, EDR
- **Network Forensics:** PCAP parsing, DNS, HTTP, beacon interval analysis
- **Email Analysis:** Header parsing (SPF/DKIM/DMARC), Reply-To pivoting, lookalike domain analysis
- **Cloud/Identity:** M365 legacy auth abuse, session/refresh-token persistence, Entra ID containment
- **Detection Engineering:** Identified two EDR alerts that fired but were never actioned

## Repository contents
- `report/`: Sanitized final investigation report (PDF)
- `methodology/`: MITRE mapping, evidence index, and IOC list
- `detections/`: Example Sigma rule for Office→PowerShell lineage
- `brief/`: 3-minute executive briefing script

## Sanitization note
All IPs are RFC 5737 documentation ranges, all domains use the reserved `.example` TLD, and the payload is a placeholder. No real client data, credentials, or live infrastructure is included. This was a training/lab exercise.

## Author
**Umar Mohammed**
