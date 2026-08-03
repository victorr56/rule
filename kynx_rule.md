```
rule Kynx_Stealer {
    meta: 
        description = "Detects Kynx Stealer by static strings" 
        author = "SOCRadar Threat Research Unit (STRU)"
        date = "2026-07-17"
        hash = "4f7e6f33e7e80b17f5c7f59ba45f3e32431b639b7d91c2bda1b26664788c8b8b"

    strings: 
        // Network
        $net1   = "X-Kynx-Token:" ascii 
        $net2   = "?cat=files" ascii
        
        // Files
        $file1  = "kynx_vmcheck.txt" ascii 
        $file2  = "kynx_files.zip" ascii
        $file3  = "kynx_early.txt" ascii
        $file4  = "som_helper.exe" ascii 
        $file5  = "crdecrypt.exe" ascii
        $file6  = "debug.txt" ascii

        // Behavior
        $beh1   = "--- KYNX DEBUG LOG ---" ascii             
        $beh2   = "=== KYNX STARTED (OWNER_UID=" ascii       
        $beh3   = "KynxCR_" ascii                            
        $beh4   = "KynxSO_" ascii                              
        $beh5   = "DevGrabber" ascii 
        $beh6   = "Priority: MCE -> DBS -> ChromeElevator -> raw copy" ascii 
        $beh7   = "[=] FINAL SCORE: %d (Target: " ascii    
        $beh8   = "[!] Being Debugged (PEB): %s (+" ascii 
        $beh9   = "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE" ascii 
        $beh10  = "MCE/DBS/CE all failed" ascii
        $beh11  = "WinSysHealth" ascii

    condition: 
        uint16(0) == 0x5A4D and 
        (
            1 of ($net*) and 2 of ($file*) and 3 of ($beh*)
        )
}
```
