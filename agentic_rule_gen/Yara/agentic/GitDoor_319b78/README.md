# GitDoor

Source: https://securelist.com/operation-shadowcloud-gitdoor/122004/

GitDoor is a modular backdoor that uses the GitHub and Ably cloud services for command and control. Deployed via DLL sideloading, it decrypts its payload in memory and downloads additional shellcode plugins to perform keylogging, credential dumping with Mimikatz, and establish reverse shells using WinPTY.

- **MAL_GitDoor_Nov2026** (yara, high): This rule keys on strong unique identifiers like a PDB path and a custom Base64 alphabet, or a combination of several specific supporting strings related to C2 and configuration.
- **HKTL_Imzimzgo_Mimikatz_Variant_Nov2026** (yara, medium): This rule detects a unique internal version string for a Mimikatz variant used by the actors behind GitDoor; this string is over 16 bytes and considered a strong anchor.
- **GitDoor_Ably_C2_Auth_Token** (sigma, high): This rule keys on a unique, hardcoded C2 authorization token seen in HTTP headers, which is a critical indicator of compromise.
- **GitDoor_Keylogger_Output_File** (sigma, high): This rule keys on the specific and unusual file path used by the GitDoor keylogger for storing captured data.
- **GitDoor_Keylogger_Flag_File** (sigma, medium): This rule keys on the creation of a specific flag file (`log.lock`) in a user's Roaming AppData folder.
- **GitDoor_Sideloading_DLL_Drop** (sigma, medium): This rule keys on the file creation of a DLL used for sideloading in a system directory, which is highly suspicious outside of specific software installations.
