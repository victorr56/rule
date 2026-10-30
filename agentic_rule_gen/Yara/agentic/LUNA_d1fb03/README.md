# LUNA

Source: https://www.elastic.co/security-labs/threat-command/luna-ransomware-attack-pattern

LUNA is cross-platform ransomware written in Rust for Windows and Linux. The Windows variant attempts to disable hundreds of services and processes before encryption. It encrypts files using an x25519/AES scheme, appends a .Luna extension, and drops a ransom note named readme-Luna.txt.

- **MAL_LUNA_Ransomware_Oct2026** (yara, medium): The rule keys on unique hardcoded strings and byte patterns specific to the LUNA ransomware, including concatenated exclusion paths, a Base64-encoded part of the ransom note, and code sequences from the binary. It covers both Windows and Linux variants.
- **LinuxLunaRansomwareNote** (sigma, high): This rule detects the creation of the LUNA ransom note at a hardcoded and malformed path on Linux, making it a highly specific and high-confidence indicator.
- **WindowsLunaDisableVeeamService** (sigma, high): This rule detects a specific command line used to disable the Veeam backup service, a behavior strongly associated with pre-ransomware activity.
- **WindowsLunaTaskkillDefender** (sigma, medium): This rule detects the specific command line used to terminate the Windows Defender anti-malware service executable, a common defense evasion technique.
- **WindowsLunaStopDefenderService** (sigma, medium): This rule detects the use of `net.exe` to stop the `WinDefend` service, a specific command associated with defense evasion.
