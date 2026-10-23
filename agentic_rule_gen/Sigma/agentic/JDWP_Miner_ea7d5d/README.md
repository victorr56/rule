# JDWP-Miner

Source: https://www.wiz.io/blog/exposed-jdwp-exploited-in-the-wild

An attack exploiting exposed Java Debug Wire Protocol (JDWP) ports to achieve remote code execution on Linux systems. A dropper script (logservice.sh) is used to deploy a custom-configured XMRig miner, which masquerades as the 'logrotate' utility. Persistence is established through numerous methods including cron jobs, systemd services, and shell startup files.

- **JDWP-Miner_Process_Killer** (sigma, high): This rule detects a highly specific and complex command line used to terminate competing processes on a compromised host.
- **JDWP-Miner_Downloader_Execution** (sigma, high): This rule combines the downloader process name with the specific output file path and source URL, making it a high-fidelity indicator.
- **JDWP-Miner_Shell_Sourcing_Persistence** (sigma, high): This rule detects the unique command structure used for persistence, which involves in-memory execution via process substitution from a shell.
- **JDWP-Miner_Masquerading_Miner_Execution** (sigma, high): This rule detects the miner's masquerading behavior by keying on its anomalous execution path, while filtering the legitimate path.
- **JDWP-Miner_Systemd_Persistence** (sigma, high): This rule detects the creation of a specifically named systemd service file in a system directory, a strong indicator of persistence.
- **JDWP-Miner_C2_Domains** (sigma, high): This rule detects network lookups for known attacker-controlled infrastructure, which are high-fidelity indicators of compromise.
