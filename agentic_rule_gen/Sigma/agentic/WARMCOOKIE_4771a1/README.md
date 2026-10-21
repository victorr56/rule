# WARMCOOKIE

Source: https://www.elastic.co/security-labs/threat-command/revisiting-warmcookie

WARMCOOKIE is an actively developed backdoor with updated handlers for executing PE files, DLLs, and scripts. Newer versions use a 'string bank' of legitimate company names for evasion, a new command-line argument (/u), and embed campaign IDs. A default SSL certificate is used across some C2 infrastructure, providing a potential tracking mechanism.

- **WARMCOOKIE_Execution_via_Rundll32** (sigma, high): This rule is precise by combining the execution of a system binary (`rundll32.exe`) with a hardcoded, malware-specific DLL path in the command line.
- **WARMCOOKIE_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a known-malicious C2 domain specific to WARMCOOKIE infrastructure.
- **WARMCOOKIE_C2_Network_Connections** (sigma, high): This rule detects network connections to a list of known-malicious C2 IP addresses specific to WARMCOOKIE infrastructure.
