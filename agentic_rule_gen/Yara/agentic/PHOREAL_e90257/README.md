# PHOREAL

Source: https://www.elastic.co/security-labs/threat-command/phoreal-malware-targets-the-southeast-asian-financial-sector

PHOREAL/RIZZO is a backdoor used by APT32, observed targeting a Vietnamese financial services institution. The malware evades defenses by loading into memory from an unsigned DLL masquerading as a system file, injected into the control.exe process. C2 communication is established with a domain stored in an RC4 encrypted resource.

- **APT_APT32_PHOREAL_Oct2026** (yara, high): The rule keys on unique GUID-based strings for a mutex, named pipe, and filename, plus a long code sequence, ensuring high precision.
- **PHOREAL_Loader_Execution_Via_Control_Panel** (sigma, high): This rule keys on the specific command line used to launch `control.exe` as a host process, combining the control panel applet with a unique GUID.
- **PHOREAL_Masquerading_DLL_Loaded** (sigma, high): This rule detects `control.exe` loading `tscon32.dll`, a non-standard DLL name used by PHOREAL, which is a highly specific combination.
- **PHOREAL_Component_DLL_Creation** (sigma, high): This rule detects a file created with a unique GUID-based name seen in PHOREAL samples, which is highly unlikely to be legitimate.
- **PHOREAL_C2_Connection** (sigma, high): This rule detects network connections to an IP address specifically identified as C2 infrastructure for PHOREAL malware.
