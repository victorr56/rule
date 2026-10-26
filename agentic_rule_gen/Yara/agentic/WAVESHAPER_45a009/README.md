# WAVESHAPER

Source: https://www.elastic.co/security-labs/threat-command/axios-one-rat-to-rule-them-all

A supply chain attack compromised the 'axios' npm package, using malicious versions to distribute a cross-platform RAT. The dropper, hidden in the 'plain-crypto-js' dependency, executed via a postinstall hook and fetched platform-specific implants for Windows, macOS, and Linux. All implants share a C2 protocol and use a distinctive, anachronistic IE8 User-Agent string for C2 communications.

- **APT_UNC1069_WAVESHAPER_Oct2026** (yara, medium): The rule keys on a highly anachronistic User-Agent string, unique C2 commands and paths, a hardcoded XOR key, and an attacker email, all shared across WAVESHAPER's cross-platform components.
- **WAVESHARPER_C2_User_Agent** (sigma, high): This rule detects the highly specific and outdated IE8 User-Agent hardcoded in the malware for C2.
- **WAVESHARPER_PowerShell_Masquerading** (sigma, high): This rule detects a process execution from a full, non-standard path used for a masquerading tool.
- **WAVESHARPER_macOS_Payload_Execution** (sigma, high): This rule detects process execution from a specific, hardcoded, and non-standard full path.
- **WAVESHARPER_Malicious_NPM_Package_Install** (sigma, high): This rule detects the initial infection vector via a specific npm package post-install script.
- **WAVESHARPER_C2_Domain** (sigma, medium): This rule detects DNS queries for a known C2 domain associated with the WAVESHAPER malware.
