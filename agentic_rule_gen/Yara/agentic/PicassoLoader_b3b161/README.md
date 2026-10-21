# PicassoLoader

Source: https://www.welivesecurity.com/en/eset-research/frostyneighbor-fresh-mischief-digital-shenanigans/

FrostyNeighbor (aka Ghostwriter, UNC1151, TA445) ran a March 2026 campaign against Ukrainian governmental organizations using spearphishing PDFs that, after server-side victim validation, deliver a RAR with a first-stage JavaScript dropper and a JavaScript PicassoLoader downloader. PicassoLoader fingerprints the host over HTTPS, receives a scheduled-task XML template and a third stage that writes a base64 Cobalt Strike beacon to %ProgramData%\ViberPC.dll, masquerading a copy of rundll32.exe as ViberPC.exe and persisting via a Run key and scheduled task. Detection can focus on the bespoke C2 URIs, the WinDataScope/ViberPC file and registry names, and the SettingTimeAPI DLL export.

- **APT_FrostyNeighbor_PicassoLoader_ViberPC_Mar2026** (yara, high): The rule targets the PicassoLoader DLL via its unique export, run key value, and C2 URL.
- **APT_FrostyNeighbor_PicassoLoader_Dropper_Mar2026** (yara, high): The rule targets the JavaScript dropper using its unique C2 communication tags, C2 domain, and persistence names.
- **FrostyNeighbor_PicassoLoader_ViberPC_Persistence_Key** (sigma, high): This rule keys on the specific 'ViberPCService' registry value and the characteristic 'ShellExec_RunDLL' command for persistence.
- **FrostyNeighbor_ViberPC_Masquerading_Execution** (sigma, high): This rule detects the execution of a masqueraded rundll32.exe ('ViberPC.exe') from an unusual path, loading the payload DLL.
- **FrostyNeighbor_PicassoLoader_File_Drop** (sigma, high): This rule keys on the creation of malware components with specific names ('ViberPC.dll', 'ViberPC.exe') in the unusual 'ProgramData' location.
- **FrostyNeighbor_PicassoLoader_Dropper_Execution** (sigma, high): This rule keys on a highly specific and unique combination of command-line arguments passed to wscript.exe by the PicassoLoader dropper.
- **FrostyNeighbor_PicassoLoader_C2_Domains** (sigma, high): This rule keys on a list of C2 domains specifically associated with the FrostyNeighbor PicassoLoader and Cobalt Strike campaign.
- **FrostyNeighbor_PicassoLoader_WinDataScope_Persistence** (sigma, high): This rule keys on the specific 'UpdateService' registry value and the associated command containing a typosquatted binary and unique arguments.
