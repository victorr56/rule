# Akira

Source: https://www.huntress.com/blog/mapping-akira-ransomware-attack

An Akira affiliate gained access to a Windows endpoint over RDP, disabled Bitdefender services, dumped LSASS with procdump.exe, exfiltrated data with Rclone, and deployed a GOST tunneling tool (masquerading as C:\PerfLogs\Temp\svchost.exe with config.dll) before encrypting Shares and removing volume shadow copies via PowerShell. Detection opportunities center on the PerfLogs staging directory, the GOST config/tunnel artifacts, and Akira log files paired with shadow-copy deletion.

- **GOST_Tunnel_Execution_via_Masqueraded_Svchost_in_Perflogs** (sigma, high): This rule detects a highly specific GOST tunnel command line, combining a masqueraded process name, a non-standard path, and tool-specific arguments.
- **Akira_Associated_PowerShell_Shadow_Copy_Deletion** (sigma, high): This rule keys on a specific PowerShell command chain used by Akira ransomware to remove volume shadow copies, combining generic tools with a specific, destructive syntax.
- **Credential_Dumping_via_Procdump_from_PerfLogs_Staging_Directory** (sigma, high): This rule detects procdump targeting lsass from an attacker staging directory, combining the executable path with the sensitive target process name.
- **Akira_Affiliate_GOST_C2_Network_Connection** (sigma, high): This rule detects network traffic to a confirmed command-and-control IP address used by the threat actor.
- **Attempt_to_Stop_Bitdefender_Service_via_Command_Line** (sigma, medium): This rule detects a common defense evasion technique by looking for command-line tools stopping services containing the specific keyword 'Bitdefender'.
- **Data_Exfiltration_via_Rclone_in_PerfLogs_Staging_Directory** (sigma, high): This rule detects Rclone execution from an unusual staging path (`C:\PerfLogs`) when spawned by a shell, indicating interactive attacker activity.
