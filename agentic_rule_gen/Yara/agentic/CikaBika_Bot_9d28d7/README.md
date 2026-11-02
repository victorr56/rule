# CikaBika Bot

Source: https://www.darktrace.com/blog/cikabika-bot-inside-a-discord-rat

CikaBika Bot is a Rust-based RAT distributed via a document-themed lure in a disk image. A Nim loader uses a UAC bypass and DLL search-order hijacking against Microsoft Edge to deploy the payload. The RAT uses Discord for command and control, supporting reconnaissance, remote command execution, and file transfers.

- **MAL_CikaBika_Bot_Nov26** (yara, medium): This rule detects the CikaBika Bot payload by matching on a combination of its unique Discord commands, hardcoded output filenames, and a specific registry key string used for a UAC bypass. Requiring three of these distinctive strings provides a high-confidence match.
- **CikaBika_UAC_Bypass_FodHelper** (sigma, high): This rule detects the modification of a registry key path almost exclusively abused for the FodHelper UAC bypass technique, making it a high-fidelity indicator.
- **CikaBika_DLL_Hijacking** (sigma, high): This rule detects file creation at a highly specific and anomalous path; a legitimate 'dbghelp.dll' does not reside in the Microsoft Edge application folder.
- **CikaBika_Loader_Execution** (sigma, high): This rule detects a specific process execution chain (PowerShell > cmd.exe) combined with a unique filename from the threat profile, creating a high-precision detection.
- **CikaBika_Fallback_DLL_Load** (sigma, medium): This rule detects the abuse of a known LOLBIN (regsvr32.exe) to load a specifically named DLL payload ('dbghelp.dll'), a combination that is highly suspicious.
- **LNK_File_Masquerading_As_Document** (sigma, medium): This rule detects a common phishing TTP where a shortcut file is given a document-like name to trick users, inspired by a specific lure file from the report.
- **CikaBika_DLL_Staging** (sigma, medium): This rule detects the creation of a file at a specific temporary path observed during the CikaBika infection chain, providing a useful hunting signal.
