# MITRE ATT&CK Mapping

This table maps the observed attacker behaviors in the Northwind Logistics incident to the MITRE ATT&CK Enterprise framework. 

| # | Technique | ID | Evidence Location |
|---|---|---|---|
| 1 | Spearphishing Attachment | T1566.001 | EML headers; `DHL_Invoice_NG-48213.xlsm` |
| 2 | User Execution: Malicious File | T1204.002 | Excel opens `.xlsm`, parent = `OUTLOOK.EXE` (03 endpoint events) |
| 3 | Command & Scripting: PowerShell | T1059.001 | `powershell.exe -NoP -W Hidden -Enc` (03 endpoint events) |
| 4 | Ingress Tool Transfer | T1105 | `GET /stage/update.ps1` from `203.0.113.45` (PCAP) |
| 5 | Scheduled Task/Job | T1053.005 | `schtasks /create /tn OneDriveSyncHelper` (Windows Security 4698) |
| 6 | Application Layer Protocol (C2) | T1071.001 | 14 beacons to `198.51.100.77:8080` every 60s (PCAP) |
| 7 | Brute Force | T1110.001 | 14 × `AUTH_FAILED` from `198.51.100.23` (02a VPN log) |
| 8 | External Remote Services (VPN) | T1133 | `AUTH_SUCCESS` on `legacy-staff`, `mfa=not_required` (02a VPN log) |
| 9 | Valid Accounts | T1078 | VPN session from `10.20.99.14` (02a VPN log) |
| 10 | Remote Email Collection (IMAP) | T1114.002 | 212 items read over legacy IMAP4 (02c M365 audit) |
| 11 | Email Forwarding Rule | T1114.003 | Rule forwards to phishing Reply-To, `DeleteMessage=True` (02c M365 audit) |
| 12 | SMB/Windows Admin Shares | T1021.002 | `Finance$` reads via `5140`/`5145` from VPN IP (02b Windows Security) |
| 13 | Exfiltration Over C2 Channel | T1041 | 47.3 MiB to VPN client (02a VPN log) *[Composition unproven]* |
