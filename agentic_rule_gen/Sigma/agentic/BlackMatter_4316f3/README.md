# BlackMatter

Source: https://www.group-ib.com/blog/blackmatter-ransomware/

BlackMatter is a ransomware family considered a successor to DarkSide and REvil, targeting both Windows and Linux systems. It uses a Salsa20/RSA-1024 encryption scheme, obfuscates API calls via hashing, and stores its configuration in a custom-named resource section. The malware terminates specific processes and services before encryption and exfiltrates system data to hardcoded C2 servers.

- **MAL_BlackMatter_Win_Oct2026** (yara, medium): This rule keys on a combination of unique constants and configuration strings specific to BlackMatter, requiring three to match for high precision.
- **BlackMatter_Service_Manipulation** (sigma, high): This rule detects the use of `net.exe` or `sc.exe` to stop or delete highly specific services, `mepocs` and `memtas`, targeted by BlackMatter.
- **Potential_BlackMatter_Disabling_Veeam_Service** (sigma, medium): This rule detects a common ransomware TTP: using `net stop` or `sc stop` to disable Veeam backup services before encryption begins.
