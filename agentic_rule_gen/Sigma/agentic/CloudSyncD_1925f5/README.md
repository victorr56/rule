# CloudSyncD

Source: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages

REF8801 poses as the Web3 venture accelerator Apex Accelerator, distributing the malicious npm packages @apexacc/cli and @apexacc/audit that download platform-specific Bun executables and fetch attacker-selected commands from hxxps://vrf.apexaccs[.]org/api/v1/vrf. macOS victims receive the CloudSyncD Mach-O dropper/backdoor, while Windows victims get a PowerShell/VBScript-staged chain ending in a block-shuffled native infostealer that decrypts Chrome App-Bound Encryption keys and exfiltrates via Telegram. The repackaged Copilot agent also reroutes OpenRouter LLM traffic and registers an attacker-controlled MCP server.

- **APT_REF8801_CloudSyncD_Infostealer_Oct2026** (yara, high): The rule targets the final Windows infostealer payload, using unique hardcoded crypto keys and LCG constants.
- **APT_REF8801_CloudSyncD_Dropper_Oct2026** (yara, high): The rule keys on a unique 32-byte decryption key and a specific decoy error message found in the CloudSyncD Mach-O dropper.
- **APT_REF8801_ApexAccelerator_Bootstrap_Oct2026** (yara, high): The rule detects the initial Apex Accelerator bootstrap components using unique GUIDs, VBScript snippets, and configuration strings.
- **APT_REF8801_Exegis_Loader_Oct2026** (yara, high): This rule detects the Exegis loader by its unique embedded Fernet encryption key and an example encrypted token.
- **REF8801_CloudSyncD_Disable_Smart_App_Control** (sigma, high): This rule detects the specific registry modification used by REF8801 to disable Windows Smart App Control, a high-confidence defense evasion TTP.
- **REF8801_CloudSyncD_PowerShell_Defender_Exclusion** (sigma, high): This rule targets a specific PowerShell command line used to add a Defender exclusion for a malware-specific path, making it a precise detection.
- **REF8801_CloudSyncD_VBS_To_PowerShell_Execution** (sigma, high): This rule detects a specific process chain and command-line arguments used by the malware's initial Windows loader, providing a high-fidelity signal.
- **REF8801_CloudSyncD_Infection_Marker_File** (sigma, high): This rule detects the creation of a unique, hidden marker file in a specific location, serving as a reliable indicator of compromise for this threat.
