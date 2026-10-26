# JOKERSPY

Source: https://www.elastic.co/security-labs/threat-command/inital-research-of-jokerspy

REF9134 uses the JOKERSPY malware, a toolset including the xcc binary and the sh.py backdoor, in intrusions targeting macOS environments. Observed activity includes reconnaissance, defense evasion via TCC database manipulation, and deployment of the open-source Swiftbelt enumeration tool. The campaign has targeted a Japanese cryptocurrency exchange.

- **APT_REF9134_JOKERSPY_xcc_Oct2026** (yara, high): The rule keys on unique PDB paths, a self-signing ID, and other specific strings for the xcc binary.
- **HKTL_Swiftbelt_macOS_Oct2026** (yara, high): This rule detects the open-source Swiftbelt tool via a unique build path and output string.
- **JOKERSPY_Swiftbelt_Execution_on_MacOS** (sigma, high): This rule detects a highly specific command line used by REF9134 to execute the Swiftbelt tool, matching the process image and multiple distinctive arguments.
- **JOKERSPY_TCC_Database_Modification** (sigma, high): This rule detects a core JOKERSPY defense evasion technique by watching for writes to the sensitive TCC.db file, filtering out the known legitimate system process.
- **JOKERSPY_Suspicious_DyLib_Drop_on_MacOS** (sigma, medium): This rule detects the actor's specific TTP of staging malicious dylibs in the `/Users/shared/keybag/` directory, a highly unusual location for such files.
- **JOKERSPY_C2_DNS_Query** (sigma, high): This rule detects a DNS query for a hardcoded, malware-specific C2 domain, which is a high-confidence indicator of compromise.
