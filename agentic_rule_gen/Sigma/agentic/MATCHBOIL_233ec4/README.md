# MATCHBOIL

Source: https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/

MATCHBOIL is a custom C# downloader used by the Russia-aligned UAC-0099 group to retrieve a hex-encoded payload from its C&C server over HTTPS, install it under %LOCALAPPDATA% and persist it via Run registry values or scheduled tasks. Between 2024 and 2026 it evolved from a Unicode-obfuscated one-shot downloader into .NET Reactor-obfuscated variants with sandbox checks, a mutex-gated execution argument, a decoy GUI and a two-minute C&C polling timer. This profile captures its install paths, filenames, mutex, HTTP headers, scheduled task names and C&C infrastructure.

- **MAL_MATCHBOIL_Downloader_Oct2026** (yara, medium): The rule keys on unique and specific strings from the MATCHBOIL downloader, including a mutex, filenames, WMI queries, regex patterns, and C2 artifacts, ensuring high precision.
- **MATCHBOIL_Persistence_Scheduled_Task** (sigma, high): This rule detects the creation of scheduled tasks using highly specific names and paths used by MATCHBOIL for persistence.
- **MATCHBOIL_Persistence_Run_Key** (sigma, high): This rule combines a specific registry value name (`DeviceMonitor`) with the associated payload path in the value's data for high precision.
- **MATCHBOIL_Payload_Installation** (sigma, high): This rule detects file creation events for highly specific payload names in their unique installation directories.
- **MATCHBOIL_Staging_File_Creation** (sigma, high): This rule keys on the creation of files with highly unusual and specific names/paths, one of which contains a unique typo.
- **MATCHBOIL_Component_DLL_Load** (sigma, high): This rule precisely detects the specific relationship between a known MATCHBOIL process and a component DLL it loads.
- **MATCHBOIL_C2_Communication_Pattern** (sigma, medium): This rule detects network requests containing unique HTTP headers or a URI path specific to MATCHBOIL C2 communications.
