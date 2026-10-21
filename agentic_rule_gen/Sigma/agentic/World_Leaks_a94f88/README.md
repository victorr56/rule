# World Leaks

Source: https://www.darktrace.com/blog/when-reality-diverges-from-the-playbook-darktrace-identifies-encryption-in-a-world-leaks-ransomware-attack

World Leaks, an affiliate-based extortion-as-a-service operation rebranded from Hunters International, was observed contradicting its encryption-free model by deploying a ransomware payload that encrypted a healthcare victim's data. The intrusion began with brute force against a Fortigate appliance in October 2025, used PsExec, WinRM and Cloudflare Tunnel for lateral movement and C2, exfiltrated 80+GB to MEGA and Backblaze via rclone, and ended with SMB-delivered world.exe/task.bat and a nine-character-prefixed README ransom note.

- **APT_WorldLeaks_DiscordRAT_Oct2025** (yara, high): The rule keys on highly unique strings from a Discord RAT, including a bot token, a channel ID, and specific command lists, ensuring high precision.
- **APT_WorldLeaks_Loader_Oct2025** (yara, medium): This rule detects a DLL sideloading component by combining three specific path and filename strings related to its operation.
- **WorldLeaksRansomNoteCreation** (sigma, high): The regex for the ransom note filename is highly specific to the World Leaks ransomware family.
- **WorldLeaksRansomwarePayloadExecution** (sigma, high): The payload name 'world.exe' is a specific indicator from the incident report.
- **WorldLeaksPowerShellModuleStaged** (sigma, high): The combination of the unusual directory `\programdata\syc\` and the filename `OpenSSHUtils.psm1` is highly suspicious.
- **WorldLeaksC2NetworkConnection** (sigma, high): This rule detects connections to specific IP:Port combinations known to be used by the threat actor.
- **RcloneExfiltrationToMEGA** (sigma, medium): This rule combines a legitimate tool `rclone.exe` with a specific command-line argument for MEGA, a known exfiltration target.
