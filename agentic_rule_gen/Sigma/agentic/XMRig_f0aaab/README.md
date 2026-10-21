# XMRig

Source: https://www.greynoise.io/blog/react2shell-exploitation-consolidates

GreyNoise telemetry shows exploitation of React Server Components CVE-2025-55182 (CVSS 10.0) consolidating onto two source IPs, 193.142.147.209 and 87.121.84.24, which generated 56% of 1.4M attempts in seven days. One operator opens reverse shells to port 12323, while the other drops XMRig cryptominer binaries from staging servers 205.185.127.97 and 176.65.132.224. Detection should focus on POST requests with unusual Next-Action headers and traffic to the listed scanner and staging infrastructure.

- **React2Shell_Reverse_Shell** (sigma, high): This rule detects a specific C2 behavior (IP and port) from the threat profile, indicating a successful compromise.
- **React2Shell_Staging_Server_Connection** (sigma, high): This rule detects connections to dedicated XMRig staging IPs, indicating a likely payload download.
- **React2Shell_Attacker_Domain_Query** (sigma, high): This rule detects DNS lookups for attacker-controlled domains listed in the threat profile.
