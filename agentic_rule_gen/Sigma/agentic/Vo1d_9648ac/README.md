# Vo1d

Source: https://www.darktrace.com/blog/unmasking-vo1d-inside-darktraces-botnet-detection

Vo1d is a large-scale Android TV botnet that uses DGA seeds to compute C2 domains and beacons to cloud-hosted infrastructure over non-standard high ports (TCP 55520/55521). The same report page also details CikaBika Bot, a Nim loader that sideloads a Rust RAT as dbghelp.dll into Microsoft Edge, uses Discord channels for C2, and exfiltrates via ngrok. Detection anchors include DGA domains sharing the seed suffixes 60b33d7929a and fc975904fc9, Vo1d C2 hosts, and CikaBika's Discord command set and Edge DLL-planting paths.

- **MAL_CikaBika_RAT_Oct2026** (yara, high): This rule detects the CikaBika Rust RAT using highly specific strings, including a hardcoded Discord bot token, a unique list of commands, and specific notification messages, making it very precise.
- **MAL_CikaBika_Loader_Oct2026** (yara, medium): This rule identifies the CikaBika loader by the combination of specific file paths and a registry key related to its DLL sideloading and UAC bypass technique.
- **CikaBika_UAC_Bypass_MS_Settings** (sigma, high): The registry key `HKCU\Software\Classes\ms-settings\shell\open\command` is a specific and known UAC bypass target, making its modification a high-fidelity indicator.
- **CikaBika_DLL_Sideloading_In_Edge** (sigma, high): `dbghelp.dll` is not a standard component of Edge; its presence in the Edge `Application` folder strongly indicates search-order hijacking.
- **Vo1d_DGA_Domain_Query** (sigma, high): The DGA seeds `60b33d7929a` and `fc975904fc9` and associated static domains are unique to the Vo1d botnet.
- **CikaBika_Recon_From_Edge** (sigma, high): A browser (`msedge.exe`) spawning system discovery tools like `tasklist.exe` is a strong anomaly indicative of code injection into the browser process.
- **CikaBika_Initial_Payload_Execution** (sigma, high): The specific filename `IfyuUapz.txt` executed from the Temp directory via `cmd.exe` is a high-confidence indicator of the initial CikaBika payload.
