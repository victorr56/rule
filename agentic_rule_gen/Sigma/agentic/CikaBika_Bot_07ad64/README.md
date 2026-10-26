# CikaBika Bot

Source: https://www.darktrace.com/blog/darktrace-releases-2024-half-year-threat-insights-2

CikaBika Bot is a Rust-based Remote Access Trojan (RAT) delivered via a phishing lure containing a disk image with a malicious LNK file. A Nim-based loader uses a UAC bypass and DLL search-order hijacking against Microsoft Edge to deploy the RAT. The malware uses Discord for command-and-control, allowing operators to perform reconnaissance, execute commands, and exfiltrate data.

- **MAL_CikaBika_Bot_Oct26** (yara, medium): The rule keys on C2 command strings, reconnaissance output filenames, and a UAC bypass artifact.
- **cikabika_bot_powershell_stager** (sigma, high): This rule detects the specific and complex PowerShell command line used by CikaBika to decode and run its next stage payload.
- **cikabika_bot_dll_hijack** (sigma, high): This rule detects the specific file path used by CikaBika for its DLL search-order hijacking persistence mechanism.
- **cikabika_bot_uac_bypass** (sigma, high): This rule detects the specific registry write that combines the ms-settings UAC bypass with CikaBika's DLL planting activity.
- **cikabika_bot_loader_execution** (sigma, high): This rule detects the execution of the uniquely named Nim loader by cmd.exe, which is the final step of the initial PowerShell stager.
- **cikabika_bot_recon_file_creation** (sigma, medium): This rule detects the creation of uniquely named files that CikaBika uses to store the output of its reconnaissance commands.
