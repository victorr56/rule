# plain-crypto-js RAT

Source: https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package

A supply chain attack against the axios npm package used a malicious dependency, plain-crypto-js, to deliver a cross-platform RAT. The malware, targeting Windows, macOS, and Linux, established persistence and exfiltrated system information before awaiting further commands. The activity is attributed to North Korean threat actors.

- **APT_DPRK_RAT_PlainCryptoJs_Oct2026** (yara, medium): The rule keys on two strong unique strings (a key and a method name) or a combination of four supporting strings (project name, commands, identifiers).
- **PlainCryptoJSRATPersistenceViaRunKey** (sigma, high): This rule precisely identifies the malware's persistence mechanism by keying on the specific registry value name (`MicrosoftUpdate`) and the script it executes (`system.bat`).
- **PlainCryptoJSRATC2CommunicationUserAgent** (sigma, high): This rule detects a highly anomalous and specific User-Agent string (IE8 on WinXP) that is hardcoded in the malware, providing a reliable C2 detection across all platforms.
- **PlainCryptoJSRATC2Domains** (sigma, high): This rule detects network callouts to actor-controlled C2 domains, which is a high-confidence indicator of compromise.
