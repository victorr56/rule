# ValleyRAT

Source: https://securelist.com/valleyrat-backdoor-adware/121175/

A signed QN Wallpaper adware installer sideloads a malicious libcef.dll that AES-decrypts and loads the ValleyRAT backdoor, a campaign attributed to Silver Fox and masquerading as adware. ValleyRAT parses a reversed UTF-16LE config, injects into svchost, optionally marks its process critical to trigger a BSOD on termination, and supports keylogging, clipboard capture, screenshotting and module loading via process hollowing.

- **APT_SilverFox_ValleyRAT_Backdoor_Oct2026** (yara, high): The rule targets the ValleyRAT payload using highly specific strings for process hollowing, defense evasion, and anti-analysis.
- **APT_SilverFox_ValleyRAT_Loader_Oct2026** (yara, high): This rule detects the ValleyRAT loader by keying on specific CEF function names it imports and internal strings like "PeLoader" and "mw_entry".
- **ValleyRAT_DisableAntiSpyware_Registry** (sigma, high): This rule detects a specific registry modification used by ValleyRAT for defense evasion.
- **ValleyRAT_Process_Chain** (sigma, high): This rule detects a specific parent-child process relationship unique to the ValleyRAT campaign.
- **ValleyRAT_PeLoader_File_Creation** (sigma, high): This rule detects the creation of a specifically named payload file by the malware's loader process.
- **ValleyRAT_Installer_Execution** (sigma, high): This rule detects the execution of uniquely named installers associated with the ValleyRAT campaign.
