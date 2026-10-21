# KREMLIN

Source: https://www.elastic.co/security-labs/threat-command/malicious-browser-extension-kremlin-banking-malware

KREMLIN is a Brazilian banking malware toolkit (REF9334) that chains obfuscated JavaScript loaders, Node.js execution, RunPE/manual mapping or SentinelOne DLL sideloading, and a Chrome/Edge extension installed by regenerating Chromium Secure Preferences HMACs and App-Bound encrypted hashes. The extension steals credentials, cookies, session storage, history, page source and keystrokes and exfiltrates RC4-encrypted ZIP archives over HTTP and WebSocket C2 whose endpoints are resolved through Ethereum smart contracts.

- **MAL_KREMLIN_Installer_Oct2026** (yara, high): This rule targets the KREMLIN C++ installer based on highly specific mutexes, unique campaign IDs, payload carving markers, and distinctive log strings.
- **MAL_KREMLIN_Loader_Oct2026** (yara, high): This rule detects KREMLIN loader stages based on a unique C2 header, a very specific decoy string, typos in WMI paths, and Ethereum smart contract addresses used for C2 resolution.
- **KREMLIN_Persistence_Scheduled_Task** (sigma, high): This rule detects the creation of scheduled tasks with highly specific names used by KREMLIN for persistence.
- **KREMLIN_PowerShell_RunPE_Loader** (sigma, high): This rule keys on a highly specific PowerShell snippet used by KREMLIN to execute its .NET RunPE component.
- **KREMLIN_SentinelOne_DLL_Sideloading** (sigma, high): This rule detects a classic DLL side-loading pattern using a legitimate SentinelOne binary to load a malicious payload.
- **KREMLIN_Headless_Nodejs_Execution** (sigma, medium): This rule detects a specific process lineage where conhost.exe with the `--headless` flag spawns node.exe.
