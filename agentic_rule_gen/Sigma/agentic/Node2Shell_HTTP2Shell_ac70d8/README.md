# Node2Shell / HTTP2Shell

Source: https://socprime.com/blog/node2shell-http2shell-detection/

Node2Shell / HTTP2Shell refers to the exploitation of CVE-2026-111497, a critical vulnerability in the Brotli compression library. The vulnerability can cause decoder crashes for denial of service, or lead to remote code execution in applications like Node.js. Post-exploitation activity includes downloading scripts and cryptominers, reconnaissance, and out-of-band callbacks on both Linux and Windows systems.

- **Node2Shell_PostExploitation_Cmd_Curl_Pipe** (sigma, high): This rule detects a specific LOLBAS chain spawned from node.exe, making it a high-fidelity indicator of post-exploitation.
- **Node2Shell_PostExploitation_Wget_Download** (sigma, high): This rule is precise due to the combination of the parent process 'node', child 'wget', and a specific script name from the report.
- **Node2Shell_PostExploitation_Ping_OOB** (sigma, medium): This rule detects a suspicious OOB callback chain; the use of dnslog.cn from a node process is anomalous and worth investigating.
- **Suspicious_OOB_Interaction_Via_Dnslog** (sigma, medium): This rule detects queries to a known OAST service often used by attackers, serving as a strong threat hunting lead.
- **Node2Shell_C2_IP_Connection** (sigma, high): This rule detects connections to a specific attacker-controlled IP address identified in the threat profile.
- **Node2Shell_C2_URL_Request** (sigma, high): This rule detects requests for specific malicious URLs hosted on an attacker-controlled server identified in the threat profile.
