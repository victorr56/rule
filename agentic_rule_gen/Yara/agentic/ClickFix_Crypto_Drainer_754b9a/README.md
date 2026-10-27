# ClickFix Crypto Drainer

Source: https://www.huntress.com/blog/mac-crypto-draining-malware

A macOS malware delivered through a ClickFix social engineering attack. The initial command downloads a Bash script which profiles the system and fetches a Go-based Mach-O stealer payload. The final payload steals credentials from browsers and the macOS Keychain and is uniquely capable of draining partial amounts from cryptocurrency wallets.

- **MAL_MacOS_ClickFix_Stealer_Oct2026** (yara, high): The rule keys on a unique 17-byte comment string, reportedly a developer comment, found in the stealer payload.
- **macos_clickfix_initial_execution** (sigma, high): This rule keys on the highly specific multi-part command line used for initial malware download, execution, and cleanup.
- **macos_clickfix_payload_execution** (sigma, high): This rule detects process execution from three distinct, high-specificity file paths used by the malware for its payload.
- **macos_clickfix_persistence_launchctl** (sigma, high): This rule detects the specific `launchctl` command line used by the malware to establish persistence via a known malicious plist file.
- **net_c2_clickfix_ip** (sigma, high): This rule keys on network connections to multiple IP addresses explicitly identified as infrastructure for this malware family.
- **dns_c2_clickfix_domain** (sigma, high): This rule detects DNS lookups for `profitnow.io`, a domain used in the malware's initial infection command.
