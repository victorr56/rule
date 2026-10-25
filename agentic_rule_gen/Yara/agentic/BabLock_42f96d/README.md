# BabLock

Source: https://www.group-ib.com/blog/bablock-ransomware/

BabLock is a ransomware family targeting Windows, Linux, and ESXi systems, first observed in mid-2022. The sophisticated Windows version employs DLL side-loading, process injection, and GPO modification for lateral movement, while the Linux/ESXi variants are based on the leaked Babuk source code. The group operates stealthily, forgoing a public data leak site and using email for communication.

- **MAL_BabLock_Oct2026** (yara, medium): The rule keys on a unique mutex, a specific build path, and other supporting strings associated with BabLock ransomware.
- **BabLock_Ransom_Note** (sigma, high): This rule detects the creation of a highly specific ransom note file name, which is a strong indicator of compromise.
- **BabLock_Buggy_Wmic_Shadow_Copy** (sigma, high): This rule targets a specific, erroneous command line used by the malware, making it a high-fidelity indicator.
- **BabLock_Scheduled_Task_Creation** (sigma, high): This rule detects a highly specific scheduled task naming convention created in the registry, unique to this threat.
- **BabLock_Side_Loading** (sigma, high): This rule detects a specific DLL side-loading pattern by pairing the host process name with the malicious DLL name.
- **BabLock_Disable_Windows_Recovery** (sigma, high): This rule detects a destructive and suspicious `bcdedit` command line that is very specific and rarely used legitimately.
- **BabLock_Lateral_Movement_GPO_Update** (sigma, medium): This rule keys on a specific combination of PowerShell arguments (`-force`, `-RandomDelayInMinutes 0`) for `Invoke-GPUpdate`.
