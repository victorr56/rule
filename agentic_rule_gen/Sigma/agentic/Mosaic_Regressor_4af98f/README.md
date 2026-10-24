# Mosaic Regressor

Source: https://www.group-ib.com/blog/bootkits/

Mosaic Regressor is a UEFI bootkit developed from the leaked HackingTeam Vector-EDK framework. It establishes persistence by embedding malicious drivers and applications into the system's firmware, which then drop a payload (IntelUpdate.exe) into the startup folder before the OS boots. The payload communicates with C2 infrastructure to download additional modules.

- **MosaicRegressorPayloadExecution** (sigma, high): This rule detects the execution of the main payload from the specific startup folder path used by Mosaic Regressor for persistence.
- **MosaicRegressorPayloadDrop** (sigma, high): This rule detects the file creation event for the Mosaic Regressor payload in its specific persistence location.
- **MosaicRegressorPayloadDataFileCreation** (sigma, high): This rule detects a specific file creation behavior of the payload, linking the process `IntelUpdate.exe` to an unusual file write operation.
- **MosaicRegressorPayloadSepFileCreation** (sigma, high): This rule detects a highly specific file creation event, linking the payload process to a unique file drop in an uncommon location.
