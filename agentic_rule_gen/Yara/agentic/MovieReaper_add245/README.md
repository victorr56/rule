# MovieReaper

Source: https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/

MovieReaper is a multi-stage, modular crimeware framework distributed as fake movie executables via malicious torrent files pushed from the compromised public torrent repository itorrents[.]org. A loader downloads shellcode in plain HTTP(S) from deadhub[.]org (fallback 193.23.118[.]155), then retrieves a second-stage C2 address stored on the Solana blockchain and deploys UAC-bypass and persistence modules that masquerade as msedge.exe under %ProgramData%\Microsoft\Windows\Telemetry.

- **MAL_MovieReaper_Loader_Oct2026** (yara, medium): The rule uses unique and specific strings for module commands, C2 paths, and an undocumented API call to detect MovieReaper.
- **MovieReaper_Masquerading_msedge_exe** (sigma, high): This rule detects the highly specific and anomalous execution path MovieReaper uses for masquerading, ensuring high precision.
- **MovieReaper_C2_Domain** (sigma, high): This rule detects DNS queries for a C2 domain exclusively used by MovieReaper.
- **MovieReaper_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses specifically identified as MovieReaper C2 infrastructure.
- **MovieReaper_C2_URI** (sigma, high): This rule detects highly specific C2 URI paths used by MovieReaper for shellcode downloads.
