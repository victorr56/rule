# Determined Attacker Uploads Malicious Webshells to Parks and Rec Management Platform Servers

Source: https://www.huntress.com/blog/parks-recreation-platform-webshell-attack

A suspected China-based actor compromised three servers of a shared parks-and-recreation management platform by registering member accounts and abusing the member file upload feature to drop .aspx webshells, then used cmd.exe and PowerShell to enumerate IIS and hunt cardholder data. On return visits the actor renamed webshells as legitimate assets, timestomped them, and injected an obfuscated dropper into a jQuery file loaded by the authentication page to harvest credentials into WebRTC/WebSocket C2. Detection should focus on IIS worker processes spawning cmd.exe/PowerShell, webshell-named .aspx files, and the attacker's workers.dev C2 endpoints.

- **IIS_Worker_Spawning_Shell** (sigma, high): This rule detects a classic webshell execution pattern by keying on the suspicious w3wp.exe parent process and shell child processes.
- **Masquerading_ASPX_Webshell_Creation** (sigma, high): This rule detects a strong indicator of webshell placement by matching the executable .aspx extension with file basenames of common static assets.
- **CCRTC_Planter_Script_Creation** (sigma, high): This rule detects the creation of malicious files with the unique "ccrtc" substring in their name within the Temp directory, a strong toolkit-specific indicator.
- **Findstr_Payment_Processor_Discovery** (sigma, high): This rule detects a highly specific findstr command line used to discover a wide range of payment processor integrations, a clear sign of financial data hunting.
