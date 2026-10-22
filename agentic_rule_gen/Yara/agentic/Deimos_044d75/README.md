# Deimos

Source: https://www.elastic.co/security-labs/threat-command/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant

Deimos is a .NET remote access implant used for initial access and persistence, evolving from the Jupyter Infostealer/SolarMarker family. It employs multi-layered obfuscation using runtime-generated variables, XOR ciphers, and Base64 encoding to deliver its final payload. Persistence is achieved via a .LNK file in the Startup folder and a custom file handler registered in the HKCU hive to launch a PowerShell loader.

- **MAL_Deimos_Implant_Oct2026** (yara, high): This rule keys on two very long, high-entropy, hardcoded XOR keys that are strong unique indicators for the Deimos implant.
- **MAL_Deimos_Installer_Oct2026** (yara, medium): This rule detects Deimos installers by combining multiple metadata strings from the 'SlimReader' lure theme, including version, copyright, and file description, providing high-confidence detection through their aggregation.
- **Deimos_Persistence_LNK** (sigma, high): This rule detects a hardcoded and specific LNK filename in the Startup folder, making it a high-confidence indicator for Deimos persistence.
- **Deimos_Dropper_File_Path** (sigma, high): This rule uses a highly specific regular expression to match an unusual file path structure used by the Deimos dropper, making false positives very unlikely.
- **Deimos_Persistence_File_Handler** (sigma, high): This rule detects the creation of a PowerShell-based command for a new file-type association in the user's hive, a known persistence TTP used by Deimos.
- **Deimos_HWID_File** (sigma, medium): This rule detects the creation of a file with an abnormally long name (96-192 characters) in the AppData\Roaming folder, matching a known Deimos artifact.
- **Deimos_C2_IP** (sigma, high): This rule detects network connections to a specific IP address identified as a Deimos C2 server, providing a high-confidence alert.
