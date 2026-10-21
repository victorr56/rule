# CikaBika

Source: https://www.darktrace.com/blog/when-ai-infrastructure-becomes-part-of-the-attack-surface

CikaBika is a Rust-based RAT delivered through a disk image containing a decoy PDF and a double-extension LNK that drops a Nim loader, which uses an ms-settings UAC bypass to plant a sideloaded dbghelp.dll in Microsoft Edge. The RAT registers each victim with Discord for C2, exposes an operator command set (!shell, !download, !sysinfo), and exfiltrates staged archives via ngrok. The same report also covers XMRig cryptomining on a compromised AWS Bedrock AI gateway and WebDAV/Discord-linked infrastructure from AI-assisted campaigns.

- **MAL_CikaBika_RAT_Oct2026** (yara, high): The rule keys on unique, high-confidence strings from the CikaBika RAT, including a Discord token, command list, and specific C2 messages.
- **MAL_CikaBika_Loader_Script_Oct2026** (yara, high): This rule detects the CikaBika PowerShell deployer by combining strings related to its two main functions: the `ms-settings` UAC bypass and a C#-based window hider.
- **CikaBikaLNKPowerShellLoader** (sigma, high): This rule detects the unique PowerShell command used by CikaBika's initial dropper, combining file I/O, an inline XOR loop, and temporary file creation.
- **CikaBikaDataExfiltration** (sigma, high): This rule detects a highly specific command line combining PowerShell's `Compress-Archive` with `curl` and a `.ngrok-free.app` URL, indicative of data staging and exfiltration.
- **CikaBikaSideloadInMSEdgePath** (sigma, high): This rule detects the creation of a DLL in a highly specific and anomalous path used for sideloading by the CikaBika RAT.
- **CikaBikaUACBypassMsSettingsHijack** (sigma, high): This rule detects modification of a specific registry key used in a well-known UAC bypass technique leveraged by CikaBika.
- **CikaBikaNimLoaderExecution** (sigma, medium): This rule detects the specific process lineage and command line for executing the CikaBika Nim loader stage.
- **CikaBikaAndRelatedC2Domains** (sigma, medium): This rule keys on a list of specific C2 and mining pool domains associated with the described campaigns.
