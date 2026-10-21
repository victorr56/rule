# RMM tool abuse (NetSupport RAT, SimpleHelp, PDQ Connect, iDrive RemotePC, Syncro, Atera, ITarian, ScreenConnect, QuickAssist/HopToDesk)

Source: https://redcanary.com/blog/security-operations/rmm-detection/

Adversaries increasingly abuse signed, legitimate remote monitoring and management (RMM) tools as loaders and persistence mechanisms, often chaining two or more RMMs on one host and using MSIExec to break process lineage. Detection should focus on renamed installers, tool-specific metadata/User-Agents, config files and tokens, RMM binaries spawning other RMMs, and newly registered C2 domains embedded in command lines. This profile captures the per-tool file, process, command-line, and network artifacts Red Canary identifies as the highest-fidelity detection anchors.

- **APT_MuddyWater_RMM_Downloader_Oct26** (yara, high): This rule keys on a full, explicit URL to a malicious payload, providing a highly specific indicator of compromise.
- **APT_MuddyWater_Abused_NetSupport_Oct26** (yara, medium): This rule detects cracked or abused NetSupport Manager clients using a combination of unique but unverified strings from the threat report.
- **MuddyWater_Deceptive_Path_WebBrowserPassView_Execution** (sigma, high): This rule detects the execution of a specific credential theft tool from a highly unusual and deceptive file path, making it a very high-confidence indicator of compromise.
- **MuddyWater_Syncro_RMM_Chaining_MSIExec** (sigma, high): This rule detects a specific RMM-chaining TTP by keying on the Syncro RMM parent process spawning the Windows Installer, indicating a likely second-stage RMM installation.
- **MuddyWater_Atera_RMM_Init_Command_Line** (sigma, medium): This rule detects the specific command-line pattern for Atera agent initialization, which is a key event for auditing or hunting for unauthorized RMM software.
- **MuddyWater_SimpleHelp_RMM_Network_Activity** (sigma, high): This rule detects SimpleHelp RMM network traffic by matching a unique and specific URI path found in its C2 communication.
- **MuddyWater_Atera_RMM_Curl_MSI_Download** (sigma, high): This rule detects a behavioral pattern where the Atera RMM agent is used as a cradle to download a second-stage MSI payload, indicating malicious RMM chaining.
