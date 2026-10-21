# PHANTOMPULSE

Source: https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault

The REF6598 campaign uses social engineering to abuse the Obsidian note-taking app's plugin system for initial access. The attack deploys PHANTOMPULL, a custom loader, which in turn reflectively loads the PHANTOMPULSE RAT. PHANTOMPULSE is a novel backdoor featuring a unique C2 resolution mechanism via public blockchain transaction data.

- **MAL_PHANTOMPULL_Loader_Oct2026** (yara, high): This rule detects the PHANTOMPULL loader using multiple unique, hardcoded encryption keys and a specific code pattern for its hashing routine, providing high-confidence detection.
- **MAL_PHANTOMPULSE_RAT_Oct2026** (yara, high): This rule detects the PHANTOMPULSE RAT via highly specific debug strings for the PE version and a combination of a unique persistence filename and command hashes for the macOS version.
- **MAL_PHANTOMPULSE_Script_Oct2026** (yara, medium): This rule detects a PowerShell script from the PHANTOMPULSE campaign by matching on unique status messages confirmed to be present in the malware.
- **PHANTOMPULSE_C2_Resolution_Via_Blockscout** (sigma, high): This rule detects the unique C2 resolution mechanism via Blockscout API calls, a highly specific and unusual behavior for legitimate software.
- **PHANTOMPULL_Loader_Download_Via_BITS** (sigma, high): This rule keys on a specific PowerShell BITS transfer command, including a unique URI path and destination file, used to download the PHANTOMPULL loader.
- **PHANTOMPULSE_MacOS_Persistence_LaunchAgent** (sigma, high): This rule detects the creation of a macOS persistence file with a highly specific, randomly generated name, making it a high-fidelity indicator.
- **PHANTOMPULL_Stager_Download_Via_PowerShell** (sigma, high): This rule targets a specific PowerShell download command, combining the `iwr` commandlet, a known malicious IP/URI, and a static output filename.
- **REF6598_PHANTOMPULSE_C2_Domains** (sigma, medium): This rule detects DNS queries for known, specific C2 domains used by the PHANTOMPULSE malware family, which are unlikely to be queried by legitimate hosts.
- **REF6598_PHANTOMPULSE_Staging_Server_IP** (sigma, medium): This rule detects network connections to a known malicious IP address used for staging malware, a strong indicator of compromise.
