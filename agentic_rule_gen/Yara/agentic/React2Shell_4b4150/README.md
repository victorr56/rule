# React2Shell

Source: https://www.wiz.io/blog/nextjs-cve-2025-55182-react2shell-deep-dive

React2Shell is an exploit for CVE-2025-55182, a critical RCE in React Server Components, heavily affecting Next.js applications. Attackers use it for initial access into cloud and container environments to perform credential harvesting, deploy cryptominers (XMRig) and sophisticated backdoors like Sliver. A notable variant is a fileless backdoor that hooks the Node.js HTTP server to execute commands via a magic URL path.

- **MAL_React2Shell_PostExploit_Oct2026** (yara, high): This rule detects backdoor and exfiltration scripts by keying on highly specific strings such as a Node.js function hook, a C2 URL, a magic backdoor path, and a unique exfiltration filename.
- **React2Shell_Persistence_With_Disguised_Crond** (sigma, high): This rule detects a suspicious execution pattern combining `nohup`, a temporary directory, and a masqueraded process name (`crond`).
- **XMRig_Miner_Masquerading_As_systemd_devd** (sigma, high): This rule keys on the specific process name `systemd-devd`, a known masquerading name for XMRig and a typo of a real system binary.
- **React2Shell_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a list of known C2 domains associated with React2Shell post-exploitation activity.
- **React2Shell_C2_Network_Connection** (sigma, high): This rule detects network connections to a hardcoded C2 IP address observed in an exfiltration script.
