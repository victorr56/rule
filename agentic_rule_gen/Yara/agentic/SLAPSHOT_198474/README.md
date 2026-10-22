# SLAPSHOT

Source: https://www.rapid7.com/blog/post/ra-netscaler-intrusions-chaining-cve-2026-88771-and-cve-2026-88779

Threat actors chained CVE-2026-88771 and CVE-2026-88779 to gain root access on Citrix NetScaler appliances. The malware, dubbed SLAPSHOT, establishes persistence via cron, rc scripts, and web shells, and uses the compromised device as a pivot point for internal reconnaissance. A separate Go-based proxy named nsvmd was also deployed for C2.

- **MAL_SLAPSHOT_Go_Tools_Oct26** (yara, medium): This rule detects SLAPSHOT's Go-based tools by combining the C2 SNI value with specific output filenames from the reconnaissance scanner.
- **SLAPSHOT_nsvmd_Proxy_Execution** (sigma, high): This rule detects the execution of the core `nsvmd` proxy tool with its specific C2 arguments, a unique combination.
- **SLAPSHOT_Webshell_Access_Pattern** (sigma, high): This rule detects access to a highly specific and unique webshell URL path pattern associated with SLAPSHOT.
- **Process_Execution_from_SLAPSHOT_Directory** (sigma, high): This rule detects process execution from malware-specific hidden directories that should not contain legitimate binaries.
- **SLAPSHOT_nsvmd_Installer_Download** (sigma, high): This rule detects a shell executing a command containing both `curl` and a specific malware download URL, indicating a pipe-to-shell execution.
- **Suspicious_NetScaler_HA_Synchronization_Command** (sigma, medium): This rule detects a highly specific NetScaler administrative command that was leveraged by the actor for lateral movement.
- **SLAPSHOT_C2_Domain_Query** (sigma, high): This rule detects DNS lookups for actor-controlled C2 domains with no known legitimate use.
