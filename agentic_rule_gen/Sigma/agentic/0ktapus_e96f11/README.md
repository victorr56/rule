# 0ktapus

Source: https://www.group-ib.com/blog/0ktapus/

0ktapus is a large-scale phishing campaign targeting employees of Okta customers to steal credentials and 2FA codes. Attackers use SMS messages with links to convincing phishing pages that impersonate Okta login portals. The compromised credentials are then exfiltrated to a Telegram channel and used to conduct supply chain attacks.

- **0ktapus_Phishing_DNS** (sigma, high): This rule detects DNS queries for the specific, high-confidence phishing domains listed in the report.
- **0ktapus_C2_IPs** (sigma, high): This rule detects network traffic to the specific C2 IP addresses associated with the 0ktapus campaign.
