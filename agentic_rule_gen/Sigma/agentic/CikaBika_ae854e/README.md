# CikaBika

Source: https://www.darktrace.com/blog/hiding-in-plain-sight-uncovering-a-multi-stage-ransomware-attack-through-behavioral-detection

Darktrace reports an unattributed multi-stage ransomware intrusion (Sliver C2, Nmap scanning, DCSync via drsuapi::DRSGetNCChanges, PSExec/WMI/RDP lateral movement, SMBv1 encryption) with C2 to Vultr VPS 137.220.59.55 and data exfiltration to Wasabi cloud storage. The same page also documents CikaBika, a Rust RAT delivered by a Nim loader via a malicious LNK that stages a fake dbghelp.dll into Edge's directory through a ms-settings UAC bypass and uses Discord channels plus ngrok for C2 and exfiltration. Detection anchors include the Sliver JA3 d6828e30ab66774a91a96ae93be4ae4c, Sliver/Vultr and Wasabi endpoints, the %TEMP%\IfyuUapz.txt payload path, the ms-settings registry hijack key, and the RAT's !shell/!download Discord command set.

- **MAL_CikaBika_RAT_Oct2026** (yara, high): The rule keys on unique strings from the CikaBika Rust RAT, including a specific command list, Discord bot token, and status messages, which can trigger the rule alone.
- **MAL_CikaBika_Deployer_Script_Oct2026** (yara, high): The rule targets a specific PowerShell deployer by combining strings from its UAC bypass logic, DLL placement paths, and embedded C# code for hiding windows.
- **CikaBika_Initial_Access_PowerShell_Stager** (sigma, high): This rule detects a highly specific combination of strings within a PowerShell script block, unique to the CikaBika staging process.
- **CikaBika_Decrypted_Payload_Execution** (sigma, high): The rule keys on a unique filename `IfyuUapz.txt` for the executed image and its parent `cmd.exe`, making it a critical and precise indicator.
- **UAC_Bypass_Via_ms-settings_Handler_Hijack** (sigma, high): This rule detects modifications to a specific registry key used for a known UAC bypass technique, which is rarely touched by legitimate software.
- **Sideloading_Via_dbghelp_dll_In_Microsoft_Edge_Folder** (sigma, high): This rule detects a file created in a highly specific, anomalous path for DLL sideloading, which is a strong indicator of compromise.
- **Sliver_C2_JA3_Hash** (sigma, high): This rule detects a specific JA3 hash linked to Sliver C2, providing a high-confidence network indicator for this threat tooling.
- **CikaBika_Ransomware_Network_Indicators** (sigma, medium): This rule lists specific IP addresses used for C2 and exfiltration by the threat actor, useful for retroactive hunting and network-level detection.
