# Supershell

Source: https://www.wiz.io/blog/wiz-research-gogs-cve-2025-8110-rce-exploit

An active exploitation campaign targets a Gogs RCE vulnerability (CVE-2025-8110) via symlink abuse to gain initial access. Attackers overwrite the .git/config file to execute commands, subsequently deploying a Go-based payload from the open-source Supershell C2 framework to establish a reverse SSH shell.

- **Supershell_Gogs_Exploit_C2_IPs** (sigma, high): This rule detects network connections to IP addresses hardcoded in the threat profile as C2 and payload servers.
