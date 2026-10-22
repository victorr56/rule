# BlackX

Source: https://securelist.com/uefi-bootkit-blackx/121539/

BlackX is a UEFI bootkit used by APT41, derived from the BlackLotus bootkit. It exploits the Baton Drop vulnerability (CVE-2022-21894) to bypass Secure Boot and deploy a kernel driver and user-mode payloads, including a .NET RAT and a sideloaded DLL runner. The malware uses cloud storage and a dedicated domain for C2 communications.

- **APT_APT41_BlackX_Driver_Oct2026** (yara, high): This rule detects the BlackX kernel driver using its unique code-signing certificate subject and serial number, both strong anchors.
- **APT_APT41_BlackX_Payload_Oct2026** (yara, medium): This rule detects BlackX payloads using a unique RC4 key or a combination of C2 domains, filenames, and other specific strings.
- **BlackX_Installer_Execution** (sigma, high): This rule is precise because it detects a unique command line signature specific to the BlackX installer, combining the process name and two unique arguments.
- **BlackX_Scheduled_Task** (sigma, high): This rule is precise because the scheduled task name 'Secure-Boot-Update' is highly specific to the BlackX bootkit's exploitation process.
- **BlackX_OxiDLLRunner_Sideloading** (sigma, high): This rule detects a specific DLL sideloading pattern by correlating a commonly abused executable name with a unique malicious DLL name from the threat profile.
- **BlackX_Payload_Drop** (sigma, medium): This rule is precise by keying on the parent-child relationship between the sideloading host process (`googleupdate.exe`) and the specific dropped payload file.
- **BlackX_C2_Domain_Query** (sigma, high): This rule detects network traffic to a known C2 domain that is explicitly mentioned as being dedicated to the BlackX malware family.
