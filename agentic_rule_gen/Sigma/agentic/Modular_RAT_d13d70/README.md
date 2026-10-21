# Modular RAT

Source: https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat

A modular RAT is delivered via a tampered installer for the Exodus crypto wallet, masquerading as a background service from 'Apple Inc'. The malware persists via a scheduled task, launching an invisible instance of the wallet which loads the in-memory payload. The RAT features VNC, SOCKS proxy, and credential theft capabilities, using Azure Table Storage as a C2 dead drop.

- **MAL_ModularRAT_Exodus_Loader_Oct2026** (yara, high): This rule keys on high-entropy cryptographic artifacts and a unique JavaScript snippet found in the malware's loader component.
- **MAL_ModularRAT_Exodus_Modules_Oct2026** (yara, medium): This rule keys on a unique PDB path, a combination of module names, or a module name plus a specific API import related to manual mapping.
- **Trojanized_Exodus_Wallet_Execution_By_RAT** (sigma, high): This rule detects the execution of `Exodus.exe` from the specific installation path `\AppData\Roaming\ExdBackupTool\` used by the malware, combined with expected parent processes for scheduled task execution or MSI custom actions.
- **Exodus_RAT_Persistence_Via_ExdBackupTool_Scheduled_Task** (sigma, high): This rule detects the creation of the specific scheduled task `ExdBackupTool` which executes the trojanized payload, a unique persistence mechanism for this threat.
- **Trojanized_Exodus_RAT_Dropped_In_AppData** (sigma, high): This rule detects the file creation of the trojanized `Exodus.exe` in the specific, non-standard path `\AppData\Roaming\ExdBackupTool\`.
- **Exodus_RAT_Proxy_Reset_Via_INetHealth_Scheduled_Task** (sigma, high): This rule detects the creation of the `INetHealth` scheduled task, which combines a specific task name with a suspicious action (`netsh winhttp reset proxy`) used for defense evasion.
- **Exodus_RAT_C2_DNS_Queries** (sigma, high): This rule detects DNS queries for a list of domains specifically identified as C2 infrastructure for this RAT.
