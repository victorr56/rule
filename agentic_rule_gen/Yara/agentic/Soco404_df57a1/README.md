# Soco404

Source: https://www.wiz.io/blog/soco404-multiplatform-cryptomining-campaign-uses-fake-error-pages-to-hide-payload

Soco404 is a multiplatform cryptomining campaign that exploits misconfigured services like PostgreSQL in cloud environments. It uses fake 404 error pages hosted on legitimate services like Google Sites to deliver platform-specific payloads, which then masquerade as system processes and establish persistence. The malware, built with Go and obfuscated with Garble, ultimately executes an XMRig miner.

- **MAL_Soco404_Payload_Oct2026** (yara, high): This rule detects Soco404 payloads via the hardcoded and highly unique XMR wallet address.
- **Linux_Soco404_Cron_Competitor_Removal** (sigma, high): This rule detects a highly specific `sed` command line used by Soco404 to remove cron jobs of other miners.
- **Windows_Soco404_Service_Persistence** (sigma, high): This rule detects service creation using `sc.exe` where the binary path matches Soco404's specific random naming convention.
- **Linux_Soco404_Cron_Persistence** (sigma, high): This rule detects a specific command line used by Soco404 to create a persistent cron job in a masqueraded directory.
- **Windows_Soco404_Payload_Download_Certutil** (sigma, high): This rule detects a specific `certutil.exe` command line used by Soco404 to download its initial payload to a suspicious path.
- **Linux_Soco404_MSR_Modification** (sigma, high): This rule detects specific `wrmsr` commands used by Soco404 to optimize CPU performance for its cryptomining payload.
- **DNS_Soco404_C2_Domains** (sigma, high): This rule detects DNS queries to command and control domains known to be exclusively used by the Soco404 campaign.
