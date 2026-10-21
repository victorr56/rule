# REF6138

Source: https://www.elastic.co/security-labs/threat-command/betting-on-bots

A multi-stage campaign targeting Linux Apache2 servers for initial access. The threat actor deploys RUDEDEVIL and KAIJI malware for cryptomining and DDoS, and uses the GSOCKET tool for persistent, masqueraded C2. The campaign also involves custom malware, privilege escalation attempts using pwnkit, and abuse of online gambling APIs.

- **APT_REF6138_Custom_Apache2_Malware_Oct2026** (yara, high): This rule keys on a unique hardcoded URI path and an encoded string from REF6138's custom apache2 malware.
- **HKTL_Ligolo_ng_REF6138_Implant_Oct2026** (yara, high): This rule detects the Ligolo-ng tool based on a hardcoded GitHub repository URL found in the binary.
- **HKTL_GSOCKET_REF6138_Implant_Oct2026** (yara, high): This rule detects the GSOCKET tool based on unique error and environment variable strings.
- **Tool_Linux_GSOCKET_MasqueradingExecution** (sigma, high): This rule detects a highly specific command line used by the GSOCKET tool for process masquerading.
- **REF6138_RUDEDEVIL_Cryptomining_Linux** (sigma, high): This rule keys on a specific cryptominer command line, including the unique wallet address, making it a high-fidelity indicator.
- **REF6138_DownloadAndPipeToInterpreter_Linux** (sigma, high): This rule detects a common malware execution pattern combined with a threat-actor-specific domain, making it precise.
- **REF6138_C2_Domains_DNS** (sigma, high): This rule detects DNS queries for high-confidence C2 domains specific to the REF6138 threat actor.
