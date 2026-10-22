# Bisonal

Source: https://www.group-ib.com/blog/tonto-team/

Tonto Team is a suspected Chinese espionage actor using phishing emails with malicious RTF documents created by the Royal Road weaponizer. The documents drop the Bisonal.DoubleT backdoor or a new downloader called TontoTeam.Downloader (aka QuickMute). The malware establishes persistence via Run keys and communicates with C2 servers over HTTP/S using custom URI patterns and RC4-encrypted data.

- **APT_TontoTeam_Downloader_QuickMute_Oct2026** (yara, high): This rule targets the Tonto Team downloader using a unique mutex, a 256-byte key, and a sscanf format string.
- **APT_TontoTeam_Bisonal_DoubleT_Oct2026** (yara, medium): This rule detects the Bisonal.DoubleT payload by combining a Base32 alphabet with URI paths and other strings from reporting.
- **TontoTeam_Bisonal_Persistence** (sigma, high): This rule detects a specific persistence mechanism used by Bisonal, combining a Run key value name and a masquerading payload path.
- **TontoTeam_Bisonal_Masquerading** (sigma, high): This rule detects Bisonal's process masquerading by keying on the execution of `conhost.exe` from an unusual and actor-specific path.
- **RoyalRoad_Dropped_Payload_TontoTeam** (sigma, medium): This rule detects a specific payload file `dcnx18pwh.wmf` dropped by the Royal Road weaponizer when launched from an Office process.
- **TontoTeam_C2_Domains** (sigma, high): This rule lists several C2 domains exclusively associated with Tonto Team, making DNS lookups for them a strong indicator of compromise.
- **TontoTeam_C2_IPs** (sigma, high): This rule detects network connections to IP addresses identified as C2 infrastructure for the Tonto Team actor's Bisonal backdoor.
