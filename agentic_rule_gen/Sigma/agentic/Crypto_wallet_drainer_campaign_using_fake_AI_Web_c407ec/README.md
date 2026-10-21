# Crypto wallet drainer campaign using fake AI/Web3 startups (Atomic Stealer on macOS)

Source: https://www.darktrace.com/blog/crypto-wallets-continue-to-be-drained-in-elaborate-social-media-scam

Evolving social-engineering campaign in which fake AI, gaming and Web3 startup companies contact cryptocurrency users over X, Telegram or Discord with a registration code and direct them to Electron apps (Windows) or DMG installers (macOS). Windows builds profile the host (HWID, MAC, GPU, RAM) and pull remote EXEs/MSIs signed with stolen code-signing certificates, while macOS builds run Atomic Stealer plus a LaunchAgent-persisted InstallerHelper that exfiltrate browser and crypto-wallet data. Stolen data is POSTed to 45.94.47.167/contact and metrics are sent to mrajhhoshoahjsd.com/collect-metrics.

- **Suspicious_Script_Download_Associated_With_macOS_Crypto_Drainer** (sigma, high): This rule combines a common download utility (`curl`/`wget`) with a specific malicious IP and filename from the threat profile.
- **DNS_Query_For_Crypto_Wallet_Drainer_Domains** (sigma, high): This rule is based on a comprehensive list of domains explicitly identified as malicious infrastructure for this campaign.
- **Network_Connection_To_Crypto_Wallet_Drainer_C2_IPs** (sigma, high): This rule detects network connections to a small set of specific IP addresses identified as C2 infrastructure in the report.
