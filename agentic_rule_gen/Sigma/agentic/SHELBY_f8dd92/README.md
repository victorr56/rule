# SHELBY

Source: https://www.elastic.co/security-labs/threat-command/the-shelby-strategy

SHELBY is a .NET malware family consisting of SHELBYLOADER and SHELBYC2 components that abuse GitHub for command and control. The malware establishes persistence via the Run registry key, performs extensive sandbox checks, and exfiltrates system information. Its reliance on a hardcoded GitHub Personal Access Token (PAT) for C2 access represents a significant operational security flaw.

- **MAL_SHELBY_Oct2026** (yara, medium): The rule keys on unique log strings, a specific hardcoded User-Agent, and combinations of internal C2 commands used by the SHELBY malware family.
- **SHELBY_Persistence_In_Run_Key** (sigma, high): This rule combines a common persistence location with a highly specific and suspicious file path used by SHELBY malware.
- **SHELBY_Malware_Component_Drop** (sigma, high): This rule detects the creation of uniquely named malware DLLs in a specific, non-standard directory created by SHELBY.
- **SHELBY_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains exclusively associated with SHELBY C2 infrastructure.
- **SHELBY_C2_IP_Connection** (sigma, medium): This rule detects network connections to a list of IPs known to be part of the SHELBY C2 infrastructure.
