# FORMBOOK

Source: https://www.elastic.co/security-labs/threat-command/formbook-adopts-cab-less-approach

FORMBOOK infostealer was delivered via a multi-stage campaign leveraging CVE-2021-40444. The attack chain involves a malicious Office document fetching a remote MHTML OLE object, leading to JavaScript execution, a PowerShell downloader, and eventual payload deployment. Later campaign phases reverted to traditional phishing attachments as the exploit was patched.

- **MAL_Formbook_Oct2026** (yara, high): This rule keys on highly specific byte sequences identified in FORMBOOK payloads.
- **FORMBOOK_PowerShell_Downloader_Script** (sigma, high): This rule detects a highly specific PowerShell script block combining a web download, a specific masqueraded filename, and process execution.
- **FORMBOOK_Masquerading_As_DllhostSvc** (sigma, high): This rule is precise by combining a specific masqueraded filename with execution from an unusual, non-system path.
- **CVE-2021-40444_Path_Traversal_Command** (sigma, high): This rule detects highly specific command-line patterns used for path traversal in CVE-2021-40444 exploitation attempts.
- **FORMBOOK_C2_IP** (sigma, high): This rule keys on a specific IP address identified as FORMBOOK C2 infrastructure in the reference report.
- **FORMBOOK_C2_DNS** (sigma, high): This rule detects DNS lookups for a list of domains identified as FORMBOOK C2 infrastructure in the reference report.
