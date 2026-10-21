# GOSAR

Source: https://www.elastic.co/security-labs/threat-command/under-the-sadbridge-with-gosar

REF3864 uses a custom loader, SADBRIDGE, to deploy GOSAR, a Golang reimplementation of the Quasar RAT. The infection chain involves DLL side-loading, UAC bypass, and process injection to deliver the implant and establish persistence. GOSAR targets Chinese-speaking users for information theft, including keylogging, clipboard monitoring, and remote access via HVNC.

- **APT_REF3864_SADBRIDGE_Loader_Oct2026** (yara, medium): The rule uses a unique COM moniker for UAC bypass as a strong anchor, backed by a constant and several high-confidence prose strings.
- **MAL_GOSAR_Implant_Oct2026** (yara, medium): The rule detects the GOSAR implant via unique Golang build paths or a combination of strings derived from prose, including a distinctive misspelling.
- **SADBRIDGE_Persistence_Service_Creation** (sigma, high): This rule detects the creation of a registry key for a service with a name specific to SADBRIDGE persistence.
- **SADBRIDGE_Staging_Directory_File_Activity** (sigma, high): This rule keys on file activity within a highly specific and unusual directory path used by the SADBRIDGE loader.
- **GOSAR_Keylogger_Data_Creation** (sigma, high): This rule detects file creation in a specific and unusual Start Menu subdirectory used by GOSAR for data exfiltration staging.
- **SADBRIDGE_Encrypted_Config_File_Creation** (sigma, high): The combination of the specific path prefix `C:\Users\Public\Documents\` and the unique filename `edbtmp.log` is a strong indicator of SADBRIDGE activity.
