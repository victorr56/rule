# SILENTCONNECT

Source: https://www.elastic.co/security-labs/threat-command/silentconnect-delivers-screenconnect

SILENTCONNECT is a multi-stage loader that begins with a VBScript lure, which downloads and executes a C# payload from Google Drive using PowerShell. The loader uses PEB masquerading, UAC bypass, and adds a Windows Defender exclusion before its final action of silently installing the ScreenConnect RMM tool for remote access.

- **MAL_SILENTCONNECT_Loader_Oct2026** (yara, high): This rule detects the SILENTCONNECT .NET loader using its unique typelib GUID, which is a strong anchor. It also uses several other unique strings and a shellcode pattern for resilient detection.
- **SILENTCONNECT_PowerShell_CSharp_Loader** (sigma, high): This rule detects a specific PowerShell script block combining download, file read, and in-memory C# compilation, characteristic of the SILENTCONNECT loader.
- **SILENTCONNECT_ScreenConnect_MSI_Download_And_Install** (sigma, high): This rule detects a PowerShell script block downloading and executing the specific ScreenConnect MSI, a core behavior of this threat.
- **SILENTCONNECT_Defender_Exclusion_For_EXE_Files** (sigma, medium): This rule detects a highly suspicious defense evasion technique where all `.exe` files are excluded from Windows Defender scans via PowerShell.
- **SILENTCONNECT_C2_DNS_Queries** (sigma, high): This rule detects DNS queries for actor-controlled domains identified in the threat profile, providing a high-confidence C2 indicator.
- **SILENTCONNECT_Payload_URL_URI** (sigma, high): This rule detects web requests for specific, structured URLs and URI paths used by SILENTCONNECT to download its payloads.
- **SILENTCONNECT_C2_IP_Address** (sigma, high): This rule detects network connections to a known actor-controlled IP address, providing a high-confidence C2 indicator.
