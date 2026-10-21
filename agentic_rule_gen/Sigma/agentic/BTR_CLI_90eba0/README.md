# BTR_CLI

Source: https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/

BTR_CLI is a research PoC that weaponizes Microsoft's signed Windows Defender Boot-Time Removal driver (BTR.sys) as an arbitrary file/registry kernel primitive by forging its RC4-encrypted, ~CRC32-validated transaction config stored in a :changelist ADS. The driver is staged as a SERVICE_SYSTEM_START (Start=1) service in the "Boot Bus Extender" group, executing in a pre-EDR "Golden Window" after the filesystem is writable but before user-mode AV services start. Detection relies on ADS creation on .sys files, System (PID 4) file/registry operations after a driver load, and non-Defender process lineage for the driver.

- **BTR_CLI_Proof_Of_Concept_Tool_Execution** (sigma, high): This rule detects the BTR_CLI PoC tool by its unique process name and specific command-line argument patterns, making it resilient to process renaming.
- **BTR_sys_Service_Configured_With_ADS_Changelist** (sigma, high): This rule detects the core TTP of passing a `.sys:changelist` ADS path as a service's `Args` parameter, which is highly specific and anomalous.
- **BTR_sys_Changelist_Alternate_Data_Stream_Creation** (sigma, high): This rule detects the creation of the specific `:changelist` ADS on a `.sys` file, a key preparatory step for the BTR exploit.
- **BTR_sys_Log_File_Creation** (sigma, high): This rule detects the creation of a specific log file (`BootClean.log`) by the `System` process, a direct and high-confidence artifact of the malicious driver's execution.
- **Suspicious_Service_Creation_In_Boot_Bus_Extender_Group** (sigma, medium): This rule detects a service being placed in the `Boot Bus Extender` group, an unusual choice for third-party software and a specific behavior of the BTR_CLI tool.
