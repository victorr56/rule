# AUDIOFIX

Source: https://www.wiz.io/blog/threat-actors-target-crypto-orgs

JINX-0164 is a financially motivated threat actor targeting the cryptocurrency industry since at least mid-2025. The group uses social engineering to deploy custom macOS malware, AUDIOFIX and MINIRAT, for credential theft and lateral movement. They have also conducted supply chain attacks against developers via trojanized NPM packages.

- **APT_JINX0164_AUDIOFIX_MINIRAT_macOS_Oct2026** (yara, medium): This rule detects the AUDIOFIX and MINIRAT binaries based on a shared high-entropy AES key and a MINIRAT-specific Go module path, both strong anchors. It also uses a combination of three hardcoded C2 domains as a fallback detection.
- **APT_JINX0164_AUDIOFIX_Dropper_Script_Oct2026** (yara, medium): This rule detects dropper scripts by combining a highly specific payload URL (from report disassembly) with other campaign-specific strings found in prose, providing a robust detection for text-based files.
- **JINX-0164_AUDIOFIX_Persistence_On_MacOS** (sigma, high): Keys on a highly specific persistence plist filename and path used by AUDIOFIX.
- **JINX-0164_MINIRAT_Persistence_On_MacOS** (sigma, high): Keys on a highly specific persistence plist filename and path used by MINIRAT.
- **JINX-0164_Dropper_Launchctl_Job_Submission** (sigma, high): Keys on a specific `launchctl` command line pattern used by the JINX-0164 dropper.
- **JINX-0164_AUDIOFIX_Stolen_Password_Cache_File_Creation** (sigma, medium): Keys on a specific filename used by AUDIOFIX to cache stolen passwords.
- **JINX-0164_AUDIOFIX_C2_And_Payload_Domains** (sigma, high): Keys on a list of specific DNS queries for C2 and payload domains tied to JINX-0164.
