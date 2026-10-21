# TELEPUZ

Source: https://www.elastic.co/security-labs/threat-command/telepuz-maas-malware-clickfix

TELEPUZ is a modular, actively developed Windows MaaS malware written in C, spread through CLICKFIX-VIDAR chains and delivered as a 64-bit DLL executed via rundll32. It uses custom RC4 string encryption, import hashing, indirect syscalls, UAC bypass and service persistence (CipherAllocator) while beaconing over WebSockets with multiple dead-drop-resolver fallback C2 mechanisms.

- **MAL_TELEPUZ_Core_Oct2026** (yara, medium): The rule keys on unique strings from the TELEPUZ core DLL, including a hardcoded AES key, a service description, file paths, and various constants, making it precise for this specific malware component.
- **TelepuzPersistenceService** (sigma, high): This rule detects the specific registry modifications TELEPUZ makes to establish service-based persistence, which are highly unique to the malware.
- **TelepuzPayloadFileCreation** (sigma, high): This rule detects the creation of TELEPUZ DLLs in highly specific and unusual file paths that are unlikely to occur in legitimate operations.
- **TelepuzPayloadExecutionRundll32** (sigma, high): This rule detects the specific command line pattern used by TELEPUZ to execute its dropped DLLs, combining rundll32 with unique file paths and export names.
- **ClickfixPowershellDropperForTelepuz** (sigma, high): This rule keys on a combination of highly specific, concatenated strings within a PowerShell command line, making it a reliable indicator for this dropper activity.
- **TelepuzSelfDeletion** (sigma, medium): This rule detects the specific self-deletion command that combines a ping-based delay with the deletion of the uniquely named `telepuz.dll` file.
- **TelepuzC2Domains** (sigma, high): This rule detects network callouts to domains that are explicitly identified as part of the TELEPUZ malware infrastructure.
