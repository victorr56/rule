# XWORM and AGENTTESLA

Source: https://www.elastic.co/security-labs/threat-command/attack-chain-leads-to-xworm-and-agenttesla

A multi-stage attack chain uses a weaponized Word document to fetch an RTF object, which in turn executes a malicious PowerShell script. The script establishes persistence, bypasses AMSI, and uses a custom .NET loader to inject either XWORM or AGENTTESLA into a legitimate process's memory. The malware exfiltrates data, with AGENTTESLA using Discord webhooks for C2.

- **MAL_AgentTesla_Oct2026** (yara, high): The rule uses multiple high-specificity strings (>=16 chars) found in AgentTesla samples, any one of which is a strong indicator of the malware.
- **XWORM_AGENTTESLA_Persistence_MOperaChrome** (sigma, high): This rule detects the creation of a scheduled task with the specific name "MOperaChrome", which is a high-confidence indicator of this threat.
- **XWORM_AGENTTESLA_File_Creation_MinMinons** (sigma, high): This rule keys on the creation of specific file names within the unique malware directory `C:\ProgramData\MinMinons\`, making it highly precise.
- **XWORM_AGENTTESLA_User_Creation_System32** (sigma, high): This rule detects the suspicious creation of a user named "System32", a highly unusual action specific to this threat actor's TTPs.
- **XWORM_AGENTTESLA_Persistence_Miguaned** (sigma, high): This rule detects the creation of a scheduled task with the specific name "miguaned", a high-confidence indicator of this threat.
