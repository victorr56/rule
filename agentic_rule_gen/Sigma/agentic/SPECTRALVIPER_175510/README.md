# SPECTRALVIPER

Source: https://www.welivesecurity.com/en/eset-research/oceanlotus-external-espionage-domestic-targeting/

OceanLotus (APT32) deployed its SPECTRALVIPER backdoor in two 2024-2026 Windows campaigns: a supply-chain compromise of the FireAnt MetaKit update server targeting Vietnamese stock investors, and a long-running intrusion into an infrastructure and transport construction corporation. SPECTRALVIPER is delivered via renamed signed side-loader executables (Toolbox.exe and dtlupdate.exe copies) with a -uiDll DLL side-load, then injects into a host process and beacons over HTTPS with encrypted host data in a Cookie header prefixed euconsent-v2= or zd_cs_pm=.

- **APT_OceanLotus_SPECTRALVIPER_Backdoor_Oct2026** (yara, high): The rule keys on unique hardcoded C2 URLs and a highly specific combination of cookie prefixes and a User-Agent string from the SPECTRALVIPER backdoor.
- **APT_OceanLotus_SPECTRALVIPER_Downloader_Oct2026** (yara, high): The rule detects the SPECTRALVIPER downloader by its unique update and C2 URLs, and combinations of its specific beaconing parameters and User-Agent string.
- **OceanLotus_SPECTRALVIPER_SideLoader_Execution** (sigma, high): This rule detects the specific command-line argument `-uiDll` used with SPECTRALVIPER's known side-loader host process names.
- **OceanLotus_SPECTRALVIPER_IntelAudioService_Execution** (sigma, high): This rule detects a highly specific combination of a masqueraded process path and unique command-line arguments used by SPECTRALVIPER.
- **OceanLotus_SPECTRALVIPER_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains exclusively associated with SPECTRALVIPER C2 infrastructure.
- **OceanLotus_SPECTRALVIPER_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses exclusively associated with SPECTRALVIPER C2 infrastructure.
