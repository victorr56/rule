# ShadowPad

Source: http://nao-sec.org/2024/06/building-caspers-shadow.html

CasperVMakerHTTPx86 ("Maker 2021329") is a ShadowPad builder that generates two files: a legitimate AppLaunch.exe copy that DLL side-loads a Casper Loader mscoree.dll, which decodes and executes embedded ShadowPad shellcode using a custom XOR/PRNG key schedule. The loader's exports (IEE2, LoadLibraryShim2, LoadStringRC2) and fixed crypto constants match Casper Loaders seen in Tick intrusions and the CVE-2021-44515 ManageEngine campaign.

- **Tick_ShadowPad_Service_Creation_With_Typo** (sigma, high): This rule detects the use of sc.exe to create a service with a unique, misspelled name, which is a strong indicator of this specific malware.
- **Tick_ShadowPad_Side-Loading_via_AppLaunch.exe** (sigma, high): This rule detects a specific DLL side-loading pattern by combining the legitimate process name with the malicious DLL's unique, misspelled path.
- **Tick_ShadowPad_Execution_from_Misspelled_Path** (sigma, high): This rule detects the execution of a process from a highly specific and unusual path containing a typo, strongly indicating the malware's presence.
