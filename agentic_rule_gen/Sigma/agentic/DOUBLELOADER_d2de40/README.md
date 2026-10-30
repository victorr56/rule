# DOUBLELOADER

Source: https://www.elastic.co/security-labs/threat-command/deobfuscating-alcatraz

DOUBLELOADER is a backdoor observed with RHADAMANTHYS, protected by the open-source ALCATRAZ obfuscator. It uses techniques like control flow flattening and instruction mutation, injects code into explorer.exe, and beacons to a hardcoded C2 IP address.

- **MAL_DOUBLELOADER_Oct2026** (yara, medium): This rule detects DOUBLELOADER via a unique string or a combination of its 'Start' export and process injection API strings.
- **HKTL_Alcatraz_Obfuscator_Oct2026** (yara, low): This rule detects the Alcatraz obfuscator by combining a unique section name and obfuscation constants.
- **DOUBLELOADER_C2_IP** (sigma, high): This rule keys on the hardcoded C2 IP address explicitly mentioned in the report, providing a high-confidence indicator of DOUBLELOADER activity.
- **DOUBLELOADER_DLL_Load** (sigma, high): This rule keys on the specific DLL filename associated with DOUBLELOADER, which is a strong indicator of compromise when loaded.
