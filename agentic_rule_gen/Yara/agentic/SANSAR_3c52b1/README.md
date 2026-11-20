# SANSAR

Source: https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware

SANSAR is a Rust-based cryptomining orchestrator that manages CPU (XMRig) and GPU (SRBMiner-MULTI) miners over a Tor C2 channel. It is deployed with a kernel rootkit (acpi_thermal_mgr) to hide processes and files, and an NVML wrapper to falsify GPU utilization. A separate backdoor, netns, uses an Ethereum smart contract to resolve its C2 address.

- **MAL_SANSAR_Orchestrator_Nov2026** (yara, high): The rule uses a unique hex pattern from the binary and a specific version string to detect the SANSAR orchestrator.
- **MAL_SANSAR_Rootkit_Nov2026** (yara, medium): This rule detects the SANSAR rootkit via its unique filename, source filename, and a Turkish comment found in the code.
- **SANSAR_Linux_Execution_From_Staging_Directory** (sigma, high): This rule detects the execution of SANSAR payloads from their hardcoded staging directory, combining two highly specific artifacts.
- **SANSAR_Linux_NVML_Hijack_Backup_File** (sigma, high): This rule detects the creation of a hidden backup file for a specific NVIDIA library, which is a unique and high-confidence indicator of the SANSAR malware.
- **SANSAR_Linux_Backdoor_Service_Configuration** (sigma, high): This rule detects the enabling or starting of the `netns.service`, a specific name used for persistence by the SANSAR backdoor.
- **SANSAR_Linux_GPU_Enumeration** (sigma, medium): This rule precisely detects the specific GPU enumeration command when spawned by the `sansar` process, a strong behavioral indicator.
- **SANSAR_Linux_C2_Onion_Domain_Query** (sigma, high): This rule detects DNS queries for the unique and hardcoded SANSAR C2 onion domain, which is a critical indicator of compromise.
