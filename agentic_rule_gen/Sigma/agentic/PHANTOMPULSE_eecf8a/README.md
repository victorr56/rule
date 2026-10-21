# PHANTOMPULSE

Source: https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole

PHANTOMPULSE is the final-stage RAT of the REF6598 intrusion set, combining three public process-injection techniques (module stomping, debug-API state machine, manual mapping), a shared hardware-breakpoint AMSI/WLDP/ETW bypass, and rundll32-hosted scheduled-task persistence of an encrypted stub DLL. It resolves its C2 URL from Ethereum/Base/Optimism transaction input via Blockscout with a hardcoded fallback panel, and its resolver lacks sender verification, making the channel sinkhole-able with one transaction.

- **APT_PHANTOMPULSE_RAT_Oct2026** (yara, high): Keys on unique debug strings and a cluster of DJB2 hash constants specific to the PHANTOMPULSE RAT.
- **PHANTOMPULSE_Scheduled_Task_Persistence** (sigma, high): This rule detects the creation of persistence tasks using highly specific names and paths from the PHANTOMPULSE threat profile.
- **PHANTOMPULSE_Persistence_Execution_via_Rundll32** (sigma, high): This rule detects a highly specific `rundll32.exe` command line targeting the unique PHANTOMPULSE DLL path and export function.
- **PHANTOMPULSE_C2_Domain_Query** (sigma, high): This rule detects network requests to high-confidence, actor-controlled C2 domains hardcoded in PHANTOMPULSE.
- **PHANTOMPULSE_Elevation_Marker_File_Creation** (sigma, medium): This rule detects the creation of a uniquely named marker file, `.elevate`, which is a specific behavior tied to the malware's privilege escalation logic.
