# WARMCOOKIE

Source: https://www.elastic.co/security-labs/threat-command/dipping-into-danger

WARMCOOKIE is a Windows backdoor distributed via phishing campaigns that use recruiting-themed lures. It fingerprints victim machines, captures screenshots, and can execute commands or deploy additional payloads. It uses a scheduled task for persistence and communicates over HTTP, sending RC4-encrypted and Base64-encoded data within the Cookie header.

- **MAL_WARMCOOKIE_Backdoor_Oct2026** (yara, high): The rule uses highly specific strings and code patterns from the WARMCOOKIE payload, any one of which is sufficient for a high-confidence match.
- **WARMCOOKIE_Persistence_Execution_Rundll32** (sigma, high): This rule detects the specific command line used by WARMCOOKIE's scheduled task for persistence, keying on rundll32.exe, the unique path, and export function.
- **WARMCOOKIE_PowerShell_Downloader** (sigma, high): This rule detects a unique combination of commands in a PowerShell script block used by WARMCOOKIE for its download and execution chain.
- **WARMCOOKIE_Scheduled_Task_Creation** (sigma, high): This rule precisely detects the command line for creating WARMCOOKIE's persistence scheduled task, using the specific task name and target executable path.
- **WARMCOOKIE_File_Drop** (sigma, high): This rule detects the creation of the WARMCOOKIE payload at its specific, non-standard path by a common scripting engine or service host.
- **WARMCOOKIE_C2_IPs** (sigma, medium): This rule detects network connections to known WARMCOOKIE C2 IP addresses from the provided threat profile.
