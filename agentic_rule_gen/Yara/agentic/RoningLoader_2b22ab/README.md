# RoningLoader

Source: https://www.elastic.co/security-labs/threat-command/roningloader

RoningLoader is a multi-stage loader attributed to DragonBreath that deploys a modified gh0st RAT. It employs various defense evasion techniques, including using a legitimately signed driver, custom WDAC policies, and PPL abuse to terminate EDR products, particularly Microsoft Defender. The final payload communicates over raw TCP and includes keylogging and clipboard hijacking capabilities.

- **APT_DragonBreath_RoningLoader_Payload_Oct2026** (yara, high): The rule targets the final Gh0st RAT payload of RoningLoader using multiple highly specific mutexes, registry keys, and hardcoded strings, including Chinese-language artifacts for keylogging.
- **APT_DragonBreath_RoningLoader_Driver_Oct2026** (yara, high): This rule detects the RoningLoader driver via a highly specific PDB path, a combination of the device name (`\\\\.\\Ollama`), and the signer's name, providing robust detection logic.
- **RoningLoader_EDR-Freeze_PPL_Abuse** (sigma, high): This rule detects a highly specific command line used for PPL abuse, combining the legitimate `ClipUp.exe` with attacker-specific arguments and paths.
- **RoningLoader_Persistence_Service** (sigma, high): This rule detects a service creation event with a highly specific, typosquatted service name unique to RoningLoader.
- **RoningLoader_Temp_Driver_Service** (sigma, high): This rule combines the specific service name `xererre1` with the unusual temporary driver filename `1912763.temp`, making it a high-fidelity indicator.
- **RoningLoader_Payload_Execution_Regsvr32** (sigma, high): This rule detects `regsvr32.exe` loading a DLL from a path (`C:\ProgramData\Roning\`) specific to the RoningLoader malware.
- **RoningLoader_Gh0st_RAT_C2_DNS** (sigma, medium): This rule detects DNS lookups for a known RoningLoader C2 domain, which is a strong indicator of compromise.
