# ClickLock Stealer

Source: https://www.group-ib.com/blog/clicklock-stealer-macos-malware/

ClickLock Stealer is a modular macOS infostealer delivered through ClickFix paste-into-Terminal lures that chains a Cloudflare-themed orchestrator, credential and Keychain stealers, a multi-chain crypto harvester and a GSocket reverse-shell backdoor, exfiltrating everything through Telegram bots and compromised WordPress domains. If the victim refuses the fake password dialog the malware locks the desktop by killing interactive processes at sub-second intervals until compliance, then timestomps and self-deletes while the gs-netcat backdoor persists.

- **ClickLock_Stealer_Persistence_Activation** (sigma, high): This rule detects the loading of malicious LaunchAgent plists with names 'com.authirity.plist' (a typo) and 'com.chromer.plist' which are specific to ClickLock Stealer.
- **ClickLock_Stealer_Password_Validation** (sigma, high): This rule detects 'dscl -authonly', a specific command used by the malware to validate stolen user credentials that is highly anomalous in legitimate use.
- **ClickLock_Stealer_Chrome_Keychain_Access** (sigma, high): This rule detects 'security' being used to access Chrome credentials when parented by a shell, a strong indicator of a credential harvesting script.
- **ClickLock_Stealer_Staging_Directory_Execution** (sigma, high): This rule detects process execution from the specific hidden staging directory `/.cacheb/` used exclusively by ClickLock Stealer.
- **ClickLock_Stealer_Timestomping_Staging_Directory** (sigma, medium): This rule detects a highly specific timestomping command that uses the '/Movies' folder as a source and the malicious '/.cacheb' directory as a target.
- **ClickLock_Stealer_C2_DNS_Query** (sigma, high): This rule detects DNS queries to domains specifically identified as C2/payload infrastructure for ClickLock Stealer.
