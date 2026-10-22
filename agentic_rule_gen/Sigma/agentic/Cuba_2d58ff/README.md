# Cuba

Source: https://www.elastic.co/security-labs/threat-command/cuba-ransomware-campaign-analysis

The Cuba Ransomware group targets organizations, gaining initial access through Exchange vulnerabilities like ProxyLogon. They deploy a range of tools including SystemBC, Cobalt Strike, and custom malware for persistence and lateral movement, before exfiltrating data and encrypting files. The BUGHATCH downloader is also used to fetch payloads, and the final ransomware appends the `.cuba` file extension.

- **APT_Cuba_Ransomware_Oct2026** (yara, high): The rule keys on long, unique ransom note strings found in Cuba ransomware samples, making it highly specific.
- **MAL_Bughatch_Downloader_Cuba_Oct2026** (yara, high): The rule detects the BUGHATCH downloader via its unique PDB path or specific dropped file name patterns.
- **MAL_Cuba_PersistenceTool_Add2_Oct2026** (yara, high): The rule keys on a high-entropy hardcoded password and other artifacts related to user creation by a Cuba-associated tool.
- **Cuba_Ransomware_Hidden_User_Account** (sigma, high): This rule keys on the specific registry path and value (`0`) used to hide the actor-created 'Mysql' user, a distinct persistence and defense evasion TTP.
- **Cuba_Ransomware_Tool_Execution_RA_EXE** (sigma, medium): This rule detects the execution of a file with a specific name (`ra.exe`) from a non-standard path for that tool (`C:\ProgramData`), a known TTP for this actor.
- **Cuba_Ransomware_C2_Domains** (sigma, high): This rule is based on a list of specific, actor-controlled C2 domains observed in the campaign.
- **Cuba_Ransomware_C2_IPs** (sigma, high): This rule is based on a list of specific, actor-controlled C2 and payload distribution IP addresses observed in the campaign.
