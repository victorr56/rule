# ARECHCLIENT2 / SECTOPRAT

Source: https://www.elastic.co/security-labs/threat-command/a-wretch-client

ARECHCLIENT2 is delivered through a multi-stage infection chain that begins with a ClickFix social engineering lure. The user is tricked into running a PowerShell command, which downloads and executes the GHOSTPULSE loader. GHOSTPULSE uses DLL sideloading and an intermediate .NET loader to reflectively load the final ARECHCLIENT2 payload into memory for information stealing.

- **MAL_ARECHCLIENT2_Payload_Oct2026** (yara, high): This rule detects the ARECHCLIENT2 final payload by its unique hardcoded Pastebin URL used to fetch a secondary C2.
- **MAL_GHOSTPULSE_Loader_Oct2026** (yara, high): This rule detects the GHOSTPULSE loader based on unique hardcoded filenames of payload components it accesses.
- **MAL_ARECHCLIENT2_DotNet_Loader_Oct2026** (yara, medium): This rule detects the .NET loader for ARECHCLIENT2 by a combination of unique two-character error codes it can produce.
- **MAL_ARECHCLIENT2_Delivery_Script_Oct2026** (yara, high): This rule detects the initial lure page or PowerShell downloaders for ARECHCLIENT2 via a unique JS function or file indicators.
- **ARECHCLIENT2_GHOSTPULSE_PowerShell_Download_Exec** (sigma, high): This rule keys on a highly specific multi-part PowerShell command line string, making it very precise.
- **ARECHCLIENT2_GHOSTPULSE_Archive_Creation** (sigma, medium): This rule detects a specific filename dropped in a common staging directory, offering moderate precision.
- **ARECHCLIENT2_C2_Domains** (sigma, high): This rule is based on a list of attacker-controlled domains specific to this threat.
- **ARECHCLIENT2_C2_IP_Connection** (sigma, high): This rule is based on a list of attacker-controlled IP addresses specific to this threat.
