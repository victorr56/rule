# Phishing Abuses RMM Tools for Persistent Access

Source: https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/

Phishing campaigns delivered a legitimate, digitally signed MSP360 RMM v2.5.0.67 installer under deceptive business-document filenames; after UAC elevation it installed MSP360 services and registry autostart entries for persistent remote access. The RMM agent then launched PowerShell to download and silently install ConnectWise ScreenConnect (ClientSetup.msi via msiexec /qn) as a redundant remote-access channel used to stage and run credential-access and collection utilities. Detection can focus on unusual RMM service installation, PowerShell spawned by RMM.Agent.exe, msiexec silent MSI installs, and ScreenConnect clients contacting non-approved infrastructure.

- **Deceptive_MSP360_RMM_Installer_Filename** (sigma, high): This rule keys on a highly specific filename pattern (_rmm_v2.5.0.67_oid*.exe) used in the campaign's phishing lures.
- **Suspicious_PowerShell_Execution_by_MSP360_RMM_Agent** (sigma, high): This rule detects a key behavioral TTP where the legitimate RMM agent process spawns PowerShell to abuse its capabilities.
- **Suspicious_Tool_Dropped_in_ScreenConnect_Temp_Folder** (sigma, high): This rule combines high-confidence malicious tool names with the specific ScreenConnect staging directories used by the actor.
- **Silent_ScreenConnect_Installation_via_PowerShell** (sigma, high): This rule detects the specific command line and parent process used to silently install the secondary RMM tool.
- **ScreenConnect_C2_Domain_Query** (sigma, high): This rule keys on a list of actor-controlled C2 domains provided in the threat intelligence report.
