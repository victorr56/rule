# PIKABOT

Source: https://www.elastic.co/security-labs/threat-command/pikabot-i-choose-you

PIKABOT is a loader and backdoor with an updated variant that uses a new unpacking method and heavy obfuscation. The core component now uses RC4 for network communications and string decryption, has a plaintext configuration in memory, and performs extensive anti-debugging and anti-analysis checks. The malware communicates over HTTPS using a hardcoded User-Agent and a list of specific API-like URIs.

- **MAL_PikaBot_Core_Oct2026** (yara, medium): Keys on a unique mutex, User-Agent, and specific code pattern characteristic of the PIKABOT core component.
- **MAL_PikaBot_Loader_Oct2026** (yara, medium): Keys on specific code patterns used by the PIKABOT loader to resolve APIs via hashing.
- **PikabotC2UserAgent** (sigma, high): This rule detects a specific hardcoded User-Agent string and filters out the legitimate Outlook process, making it a high-fidelity behavioral indicator.
- **PikabotPowerShellDownloadAndExecution** (sigma, high): The rule combines the execution of powershell.exe with several specific command-line arguments and patterns (Invoke-WebRequest, OutFile to Users\Public, and the 'saps' alias), creating a highly specific detection for this malware behavior.
- **PikabotC2DnsQuery** (sigma, high): This rule detects DNS queries for domains explicitly listed as PIKABOT infrastructure, which is a high-confidence indicator of compromise.
- **PikabotC2NetworkConnection** (sigma, high): This rule detects network connections to IP addresses explicitly listed as PIKABOT C2 servers, which is a high-confidence indicator of compromise.
