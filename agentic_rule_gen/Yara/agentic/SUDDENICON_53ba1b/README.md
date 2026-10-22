# SUDDENICON

Source: https://www.elastic.co/security-labs/threat-command/elastic-users-protected-from-suddenicon-supply-chain-attack

SUDDENICON is a payload delivered in a supply chain attack targeting users of the 3CXDesktopApp. A trojanized ffmpeg.dll loads SUDDENICON from another malicious DLL (d3dcompiler_47.dll) using a static RC4 key. The malware then contacts C2 domains, which are decoded from icon files hosted on GitHub, to download a second-stage infostealer.

- **MAL_SUDDENICON_Windows_Oct2026** (yara, high): This rule keys on a strong static RC4 key, a detection string, and a combination of supporting strings from the SUDDENICON supply chain attack on Windows.
- **MAL_SUDDENICON_macOS_Oct2026** (yara, high): This rule detects the macOS version of SUDDENICON using its static RC4 key and a combination of unique filenames dropped by the malware.
- **SUDDENICON_Tainted_3CXDesktopApp_Module_Load** (sigma, high): This rule detects the core DLL side-loading behavior of the trojanized 3CXDesktopApp, making it a high-confidence indicator of this specific supply chain attack.
- **SUDDENICON_C2_DNS_Query** (sigma, high): This rule detects network traffic to a list of C2 domains exclusively used by the SUDDENICON malware.
- **SUDDENICON_Malware_File_Creation_on_macOS** (sigma, high): This rule detects the creation of uniquely named files in a specific application support path, which are strong indicators of SUDDENICON on macOS.
- **SUDDENICON_Manifest_File_Creation** (sigma, high): This rule detects the creation of a specific file (`manifest`) by a specific process (`3CXDesktopApp.exe`) in an unusual path (`C3XDesktopApp`), making it a precise indicator.
- **SUDDENICON_Malicious_Installer_File** (sigma, medium): This rule detects specific, known-bad installer filenames associated with the SUDDENICON campaign, providing an indicator of initial compromise.
