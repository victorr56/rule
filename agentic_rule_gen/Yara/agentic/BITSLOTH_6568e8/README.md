# BITSLOTH

Source: https://www.elastic.co/security-labs/threat-command/bits-and-bytes-analyzing-bitsloth

BITSLOTH is a Windows backdoor that abuses the Background Intelligent Transfer Service (BITS) for command and control. First observed in an intrusion in the LATAM region, it features numerous handlers for discovery, execution, and data collection, including keylogging and screen capturing. Analysis of embedded strings suggests the developers may be native Chinese speakers.

- **MAL_BITSLOTH_Backdoor_Oct2026** (yara, medium): The rule uses a combination of strong anchors (a unique mutex, specific hex patterns) that can fire alone, and combinations of other unique and supporting strings, including custom commands, distinctive filenames and URI format strings.
- **BITSLOTH_Execution_Via_BITS_Job** (sigma, high): This rule detects the execution of a BITSLOTH payload from a hardcoded, non-standard path.
- **BITSLOTH_Side_Loaded_DLL** (sigma, high): This rule detects BITSLOTH's side-loaded DLL from a specific, non-standard file path.
- **BITSLOTH_Staged_Data_Collection_Files** (sigma, high): This rule is based on the highly specific, hardcoded filenames used for staging collected data.
- **BITSLOTH_C2_Network_Connection** (sigma, high): This rule detects network connections to a list of known BITSLOTH C2 server IP addresses.
- **BITSLOTH_C2_URI_Paths** (sigma, high): This rule detects a highly specific URI path used by BITSLOTH for exfiltrating process information.
