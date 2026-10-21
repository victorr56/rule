# micDown

Source: http://nao-sec.org/2023/08/groundpeony-crawling-with-malice.html

GroundPeony (UNC3347) is a China-nexus APT active since at least 2021, targeting government, research and telecom organizations in Taiwan and Nepal through spear-phishing and compromised legitimate websites. Its March 2023 chain delivers a ZIP containing fake update EXEs that stage mic.exe alongside a sideloaded version.dll, which decrypts mic.doc/mic.ver and runs the micDown shellcode downloader beamed at a C2 host/port stored in its config. The group was the earliest known exploiter of CVE-2022-30190 (Follina), using it during the vulnerability's zero-day window.

- **APT_GroundPeony_micDown_Components_Oct2026** (yara, high): The rule uses a unique decoy URL and a long Chinese lure string as strong anchors, and a combination of specific KB numbers, a filename, and a C2 domain as supporting evidence to detect GroundPeony's delivery components.
- **APT_GroundPeony_micDown_Loader_Oct2026** (yara, medium): This rule detects the micDown loader by identifying a DLL that exports the common `VerQueryValueW` function but also contains at least two of the specific filenames (`mic.doc`, `mic.ver`, `mic.exe`) used in the infection chain.
- **GroundPeony_MicDown_SideLoading** (sigma, high): This rule detects the core DLL side-loading behavior of micDown, combining the specific executable path and the loaded malicious DLL name.
- **GroundPeony_MicDown_File_Creation** (sigma, high): This rule detects the creation of the specific encoded payload and C2 configuration files in the actor's dedicated staging folder, a high-fidelity indicator.
- **GroundPeony_MicDown_Execution** (sigma, high): This rule detects the execution of the sideloading host process from its specific path, anchored to its known parent dropper process names for high precision.
- **GroundPeony_Dropper_Execution** (sigma, medium): This rule detects the specific Chinese-language dropper filename used by the actor, constrained to execution from user-writable paths to reduce false positives.
- **GroundPeony_C2_Domains** (sigma, high): This rule detects DNS lookups for actor-controlled domains identified in the threat profile, which are strong indicators of compromise.
- **GroundPeony_C2_IPs** (sigma, high): This rule detects network connections to actor-controlled C2 IP addresses, which are strong indicators of compromise.
