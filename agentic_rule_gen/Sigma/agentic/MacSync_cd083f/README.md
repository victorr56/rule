# MacSync

Source: https://securelist.com/macsync-new-version/121383/

MacSync is a macOS infostealer and backdoor family distributed under MaaS via fake crypto-wallet apps (e.g. Toria), malicious DMGs and iCloud calendar scripts. This version uses binary Objective-C/Swift droppers, AES-CBC/GCM-encrypted modules, ECDH Curve25519 key wrapping via the custom pkgunpack utility, and an HTTP C2 requiring the X-Upload-Token header. It steals browser, crypto-wallet and developer credentials, verifies the admin password via the PAM API, and persists through a com.apple.finder.agent LaunchAgent, .zshrc injection and Git hooks.

- **macos_macsync_keychain_partition_mod** (sigma, high): This rule detects a highly specific and unusual command line used by MacSync to access keychain data, making it a high-confidence behavioral indicator.
- **macos_macsync_c2_communications** (sigma, high): This rule detects specific and structured URI paths unique to MacSync's C2 protocol, providing a high-fidelity network detection.
- **macos_macsync_staging_archive** (sigma, high): This rule keys on the specific, hardcoded filename `/tmp/osalogging.zip` used by MacSync for staging stolen data.
