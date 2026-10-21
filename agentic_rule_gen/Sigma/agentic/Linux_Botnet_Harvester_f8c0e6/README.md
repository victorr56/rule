# Linux Botnet/Harvester

Source: https://www.huntress.com/blog/codex-part-two

Threat actors, tracked as Actor B and C, compromised a Linux system via CVE-2025-55182 (React2Shell) to deploy a multi-revenue botnet and credential harvester. The malware uses cron jobs, systemd services, and UDEV rules for persistence while running cryptominers, selling bandwidth, and exfiltrating sensitive data. The campaign uses several custom scripts and ELF binaries downloaded from staging servers.

- **MAL_LinuxHarvester_Dropper_Oct2026** (yara, high): The rule detects dropper scripts by a unique hardcoded download URL, which is a strong indicator for this campaign.
- **Linux_Codex_Botnet_Masquerading_Miner** (sigma, high): This rule detects a highly specific file execution path used by the malware to masquerade as a legitimate system service.
- **Linux_Codex_Botnet_Dropper_Execution** (sigma, high): This rule is based on the specific `curl` command line, including the C2 IP and filename, used for initial compromise.
- **Linux_Codex_Botnet_Systemd_Persistence** (sigma, high): This rule keys on the specific, hidden file paths used by the malware to create systemd-based persistence.
- **Linux_Codex_Botnet_Cron_Persistence** (sigma, high): This rule detects the creation of a cron job at a specific, attacker-chosen path for persistence.
- **Linux_Codex_Botnet_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a highly unusual and specific C2 domain associated with this threat.
- **Linux_Codex_Botnet_C2_And_Mining_IPs** (sigma, high): This rule detects network connections to a set of IP addresses specifically used by the malware for various C2 functions.
