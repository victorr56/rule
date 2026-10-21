# ScreenConnect backdoor

Source: https://www.malware-traffic-analysis.net/2026/09/14/index.html

A malicious email impersonating the Social Security Administration delivers a fake SSA statement page (icci-sa.com) that serves a customized ScreenConnect client installer. After execution the installer establishes an outbound ScreenConnect C2 session to its relay instance over TCP 443, giving the operator remote access to the victim host.

- **ScreenConnect_Backdoor_Campaign_DNS** (sigma, high): This rule detects DNS queries for specific, attacker-controlled domains used for payload delivery and C2, making it a high-fidelity indicator.
- **ScreenConnect_Backdoor_Campaign_Network** (sigma, high): This rule detects network connections to specific, attacker-controlled IP addresses used for payload delivery and C2, making it a high-fidelity indicator.
- **ScreenConnect_Backdoor_Download_URL** (sigma, high): This rule keys on a highly specific URL path containing typosquatting elements, used exclusively for malware delivery in this campaign.
