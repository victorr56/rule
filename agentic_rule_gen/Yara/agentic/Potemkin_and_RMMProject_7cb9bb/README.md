# Potemkin and RMMProject

Source: https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack

Potemkin is a custom loader that uses a deterministic Domain Generation Algorithm (DGA) and reflective loading to deliver its payload. The main payload, RMMProject, is a Lua-scriptable RAT featuring browser credential theft with a Chrome App-Bound Encryption bypass, a hidden remote desktop module, and process injection capabilities. The malware establishes persistence via Run keys and creates a unique identifier file on disk to track victims.

- **MAL_Potemkin_Loader_Oct2026** (yara, medium): The rule uses unique log messages and DGA artifacts specific to the Potemkin loader.
- **MAL_RMMProject_RAT_Oct2026** (yara, high): The rule keys on highly specific strings from the RMMProject RAT, including unique log messages and SQL queries for credential theft.
- **MAL_EtherRAT_Oct2026** (yara, high): This rule detects EtherRAT using a unique hardcoded build identifier (GUID), which is a strong and reliable indicator.
- **Potemkin_Loader_Persistence_Via_RunSearch_Run_Key** (sigma, high): This rule keys on the specific registry value name 'RunSearch' and the corresponding executable path in the registry value data.
- **Potemkin_Loader_Execution_From_AppData** (sigma, high): This rule keys on the specific and unusual installation path and executable name 'RunSearch.exe' used by the Potemkin loader.
- **Potemkin_Loader_Client_ID_File_Creation** (sigma, high): This rule keys on the creation of the unusually named 'hyper-v.ver' file in an atypical location, 'AppData\Local'.
- **Potemkin_Loader_C2_Communication** (sigma, high): This rule keys on a list of specific URI paths used exclusively by Potemkin for C2 communications.
- **Scheduled_Task_msiInstall2_For_Remote_MSI_Installation** (sigma, high): This rule keys on a specific scheduled task name, 'msiInstall2', combined with commands to download and run a remote MSI.
- **HTA_Payload_Execution_Via_Program_Compatibility_Assistant** (sigma, high): This rule keys on the abuse of 'pcalua.exe' to launch 'mshta.exe' with a remote payload, a highly suspicious combination.
