# Sliver

Source: https://www.wiz.io/blog/ivanti-epmm-rce-vulnerability-chain-cve-2025-4427-cve-2025-4428

Threat actors are exploiting a vulnerability chain (CVE-2025-4427, CVE-2025-4428) in Ivanti Endpoint Manager Mobile (EPMM) to achieve remote code execution. Post-exploitation activities include deploying Sliver beacons, JSP web shells like Behinder, and establishing reverse shells. Attackers have also been observed dumping credentials from the underlying MySQL database.

- **SUSP_Ivanti_EPMM_Post_Exploit_Script_Oct2026** (yara, medium): This rule keys on a combination of product-specific database table names and infrastructure IOCs associated with post-exploitation activity.
- **IvantiEPMM_ExploitAttempt** (sigma, high): This rule detects attempts to exploit a specific Ivanti EPMM vulnerability by keying on the unique and vulnerable API URI paths.
- **IvantiEPMM_WebshellCreation** (sigma, high): This rule detects the creation of webshells in very specific, actor-used paths within the Ivanti EPMM directory structure.
- **Linux_ReverseShell_IvantiEPMM** (sigma, high): This rule precisely detects a specific reverse shell command line pattern by combining the process image with multiple specific arguments.
- **Network_IvantiEPMM_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses specifically identified as C2 infrastructure in this campaign.
- **DNS_IvantiEPMM_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains specifically identified as C2 infrastructure in this campaign.
- **Proxy_IvantiEPMM_Payload_URLs** (sigma, high): This rule detects network access to specific, attacker-controlled URLs used to host malicious payloads or commands.
