# Antino

Source: https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/

UAT-11587 is a China-nexus intrusion set targeting government, defense and policy organizations across Asia with a five-stage spear-phishing chain that ultimately delivers the Rust-compiled Antino backdoor via signed-host DLL sideloading of slc.dll through GatherOsState.exe. Antino performs host reconnaissance, command/PowerShell execution, file transfer, in-memory shellcode loading and registry Run-key persistence, and uses Microsoft 365 (Outlook and OneDrive via Microsoft Graph) as dead-drop C2 to blend into legitimate cloud traffic.

- **APT_UAT11587_Antino_Backdoor_Oct2026** (yara, high): This rule detects the Antino backdoor using unique PDB paths, a specific PowerShell command for persistence, and a combination of other unique strings from its C2 and command handling logic.
- **APT_UAT11587_Antino_TestAssembly_Oct2026** (yara, high): This rule detects the Antino TestAssembly.dll downloader by its unique assembly GUID and a combination of its assembly name and deserialization gadget strings.
- **Antino_Persistence_Registry** (sigma, high): This rule detects the specific registry Run key value used by Antino for persistence, combining the key path with a highly characteristic executable path in the value.
- **Antino_DLL_Sideloading** (sigma, high): This rule detects the specific DLL sideloading pattern used by Antino by correlating the legitimate host process `GatherOsState.exe` with the malicious module `slc.dll`.
- **Antino_Staging_Directory_Activity** (sigma, high): This rule detects the creation of specific malware components within the unique staging directory `\Windows GatherOSStateKit\` used by the Antino backdoor.
- **Antino_Execution_via_Scripted_Diagnostics** (sigma, medium): This rule detects a specific defense evasion technique where sdiagnhost.exe writes a malicious PowerShell script to a known temporary location for execution.
- **Antino_C2_Domains** (sigma, medium): This rule detects DNS queries for domains specifically identified as part of the Antino C2 infrastructure, including highly unique subdomains on shared services.
