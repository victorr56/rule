# NetamLoader

Source: https://securelist.com/netamloader/121676/

NetamLoader is a sophisticated, multi-stage .NET loading framework observed in a supply-chain attack targeting government entities in Asia. It uses AppDomainManager injection via legitimate tools, XAML-based loaders, and an AMSI bypass to execute its final C2 plugin in a separate dllhost.exe process. The malware is characterized by its use of complex layered encryption, long sleep timers, and unique logic for anti-analysis and forensic evasion.

- **MAL_NetamLoader_Oct2026** (yara, high): The rule keys on highly specific GUIDs, encryption keys, and .NET type names used abusively by NetamLoader.
- **NetamLoader_COM_Hijacking_Persistence** (sigma, high): This rule detects a specific COM hijacking persistence technique by combining the unique CLSID and the "DllSurrogate" value, making it a high-fidelity indicator for NetamLoader.
- **NetamLoader_Execution_Via_PatchMyPC_ScriptRunner** (sigma, high): This rule detects the core execution behavior of NetamLoader by matching the use of a legitimate binary from a specific, malware-related path with actor-specific command-line arguments.
- **NetamLoader_Configuration_File_Creation** (sigma, high): This rule precisely identifies NetamLoader's staging activity by detecting the creation of its specific configuration and payload files in a unique directory.
- **NetamLoader_Forensic_Evasion_Via_File_Deletion** (sigma, medium): This rule detects specific anti-forensic behavior by targeting the deletion of log and prefetch files directly related to the malware's execution host process.
- **NetamLoader_C2_Domain_Query** (sigma, high): This rule detects C2 communication attempts by matching DNS queries for a known NetamLoader C2 domain.
