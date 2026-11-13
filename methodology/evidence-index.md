# Evidence Index

Each claim in the investigation report can be reproduced using the files, event IDs, and filters listed below. PCAP rows are referenced by UTC timestamp as the capture was analyzed via direct packet parsing. 

| Claim | File | Event, field or Wireshark filter | Frame / timestamp / row |
|---|---|---|---|
| Sender, Reply-To, SPF/DKIM/DMARC | Email .eml | `From`, `Reply-To`, `Authentication-Results` headers | Headers |
| Lookalike domain queried | PCAP | `dns.qry.name contains "dhl-invoices-ng"` | 07:51:32.100Z |
| Stage-2 download, 94 bytes | PCAP | `http.request.uri contains "/stage/"`; Follow TCP stream | TCP 07:51:33.200Z |
| PowerShell User-Agent on non-browser traffic | PCAP | `http.user_agent contains "WindowsPowerShell"` | 07:51:33.200Z; 07:52:31Z to 08:05:34Z |
| Beacon to 198.51.100.77:8080 | PCAP | `ip.dst == 198.51.100.77 & tcp.flags.syn == 1 & tcp.flags.ack == 0` | 14 SYNs, 07:52:31Z to 08:05:34Z |
| No request to /portal/view | PCAP | `http.request.uri contains "/portal/"` returns no packets | None |
| Normal intranet traffic | PCAP | `ip.addr == 10.20.1.20 & http` | 10.20.1.20 to 10.20.5.34:64011 |
| Attachment saved/opened; Office-to-PowerShell lineage | 03 endpoint events | EventID 11 (Outlook writes .xlsm); ProcessCreate `EXCEL.EXE` parent `OUTLOOK.EXE`; ProcessCreate `powershell.exe` parent `EXCEL.EXE` | Lines 11, 12, 13 |
| Stage-2 connection and file written | 03 endpoint events | NetworkConnect to 203.0.113.45:80; EventID 11 `%TEMP%\svcupdate.ps1` | Lines 14, 15 |
| Task creation | 03 endpoint events | `schtasks.exe /create /tn "OneDriveSyncHelper" ...` parent `powershell.exe` | Line 16 |
| Task first run | 03 endpoint events | `powershell.exe -File svcupdate.ps1`, parent `svchost.exe`, then NetworkConnect | Lines 22, 23 |
| EDR alerts | 03 endpoint events | `EDR-20261027-0042` (Medium); `EDR-20261027-0045` (Low) | Lines 17, 24 |
| VPN brute force | 02a VPN log | `AUTH_FAILED` x14 for ngozi from 198.51.100.23 | Lines 18-31 |
| MFA-free VPN success | 02a VPN log | `AUTH_SUCCESS` with `mfa=not_required` `profile=legacy-staff` | Line 32 |
| Task registered | 02b Windows Security | EventID 4698, TaskName OneDriveSyncHelper, 07:52:10Z | Identified by EventID/timestamp |
| Failed/successful logins; Finance share reads | 02b Windows Security | EventIDs 4625, 4624, 5140, 5145 (ngozi; 10.20.99.14 to \NW-FS01\Finance$) | Identified by EventID/timestamp |
| IMAP legacy auth, mailbox read, inbox rule | 02c M365 audit | IMAP4 sign-in `a7c41e90`; `MailItemsAccessed`; `New-InboxRule` | Identified by operation/timestamp |
| Password reset and surviving token | 02b / 02c | EventID 4724 at 08:40:05Z; `TokenRefresh` at 08:58:10Z | Identified by EventID/timestamp |
