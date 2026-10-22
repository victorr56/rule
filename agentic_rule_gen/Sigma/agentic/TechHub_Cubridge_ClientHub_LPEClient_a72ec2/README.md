# TechHub, Cubridge, ClientHub, LPEClient

Source: https://securelist.com/lazarus-operation-flashhole/121541/

Lazarus Group targets South Korean organizations using watering-hole attacks against mandatory security software (CrossWeb EX). The complex, memory-resident infection chain deploys a modular framework including TechHub for GitHub-based C2, Cubridge as an orchestrator, and LPEClient for advanced system profiling. The malware uses advanced evasion, DLL side-loading, and post-quantum cryptography (ML-KEM) for C2 communications.

- **APT_Lazarus_Cubridge_Oct2026** (yara, medium): The rule keys on high-entropy authentication tokens, a ZipCrypto password, and a long list of C2-related keywords, all specific to the Cubridge malware.
- **APT_Lazarus_LPEClient_Oct2026** (yara, medium): The rule is based on a cluster of four unique 32-bit message ID constants specific to the LPEClient component, combined with a supporting string identifying a less common cryptographic primitive.
- **APT_Lazarus_TouchShift_Loader_Oct2026** (yara, medium): This rule detects the TouchShift loader via a unique, 16-byte high-entropy XOR key that is a strong indicator for this malware.
- **Lazarus_TechHub_Persistence_Execution** (sigma, high): This rule detects a highly specific command line, combining a unique executable path and a hardcoded argument used by the TechHub malware.
- **Lazarus_Initial_Compromise_Process_Chain** (sigma, high): This rule detects an anomalous and specific parent-child process relationship observed during the initial compromise stage of the attack.
- **Lazarus_TechHub_Persistence_Service_Creation** (sigma, high): This rule detects the creation of a Windows service with a service binary path pointing to a specific malicious file location used by the actor.
- **Lazarus_Operation_Flashhole_C2_Domains** (sigma, high): This rule detects DNS lookups for a list of domains exclusively controlled by the threat actor for C2 and watering hole attacks.
- **Lazarus_TechHub_TouchShift_File_Artifacts** (sigma, high): This rule detects the creation of specific malware components within a directory (`RasConv`) exclusively used by this Lazarus Group toolset.
