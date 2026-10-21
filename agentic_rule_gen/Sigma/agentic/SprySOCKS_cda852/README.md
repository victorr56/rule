# SprySOCKS

Source: https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/

SprySOCKS is a FishMonger backdoor, previously Linux-only, that now has two Windows variants: WIN_DRV, which uses the RawWNPF kernel driver to hide its connections, processes, files and registry keys and to divert TCP traffic, and WIN_PLUS, which persists as a print processor. Both are delivered via DLL side-loading, decrypt their components from AES-ECB-encrypted .dat containers, inject the backdoor into svchost.exe via process doppelgänging, and speak a custom TCP/UDP/WebSocket C&C protocol with more than 30 commands.

- **APT_FishMonger_SprySOCKS_Backdoor_Oct2026** (yara, medium): The rule keys on hardcoded AES keys, unique mutexes, and version strings of the SprySOCKS backdoor.
- **APT_FishMonger_SprySOCKS_Loader_VSPMsg_Oct2026** (yara, high): The rule detects the SprySOCKS WIN_PLUS loader by its unique exported function names or a combination of its hardcoded mutex, filename, and version string.
- **FishMonger_SprySOCKS_Persistence_PrintProcessor** (sigma, high): This rule keys on the highly specific and unusual print processor registry key and DLL name used by SprySOCKS for persistence.
- **FishMonger_SprySOCKS_Persistence_IFEO** (sigma, high): This rule detects the specific combination of the vds.exe IFEO key and the misspelled malware executable name, which is a strong indicator of compromise.
- **FishMonger_SprySOCKS_Persistence_ScheduledTask** (sigma, high): This rule keys on the highly specific and misspelled arguments used to create the SprySOCKS persistence scheduled task.
- **FishMonger_SprySOCKS_WIN_PLUS_Loader** (sigma, high): This rule detects the specific SprySOCKS loader DLL being loaded by the print spooler service, a key step in its execution chain.
- **FishMonger_SprySOCKS_Driver_Service_Creation** (sigma, high): This rule detects the specific service name and driver file combination used by SprySOCKS to load its rootkit component.
- **FishMonger_SprySOCKS_Keylogger_Artifact** (sigma, high): This rule detects the creation of the specific SprySOCKS keylogger output file by svchost.exe, where the backdoor is injected.
