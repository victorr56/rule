# NOVABLIGHT

Source: https://www.elastic.co/security-labs/threat-command/maas-appeal-an-infostealer-rises-from-the-ashes

NOVABLIGHT is a NodeJS-based Malware-as-a-Service (MaaS) infostealer, distributed via platforms like Telegram and Discord. It features extensive data theft capabilities, sandbox evasion, system sabotage, and injection modules for Electron applications. The malware is under active development and uses heavy, multi-layered obfuscation to hinder analysis.

- **MAL_NOVABLIGHT_Infostealer_Oct2026** (yara, medium): Rule keys on a single confirmed string and a set of high-confidence, unverified strings from prose, requiring a 3-of-N match for detection.
- **NOVABLIGHT_C2_Domains** (sigma, high): This rule detects DNS queries to domains specifically used by the NOVABLIGHT MaaS platform, which is a critical indicator of compromise.
- **NOVABLIGHT_Volume_Shadow_Copy_Deletion** (sigma, high): This rule detects the specific command line used by NOVABLIGHT to delete all Volume Shadow Copies, a high-impact action indicative of sabotage.
- **NOVABLIGHT_Windows_Recovery_Environment_Sabotage** (sigma, high): This rule detects the specific and unusual command to disable the Windows Recovery Environment, matching a known NOVABLIGHT sabotage technique.
- **NOVABLIGHT_Lock_File_with_ICACLS** (sigma, high): This rule detects a highly specific and uncommon 'icacls' command line pattern used by NOVABLIGHT to make its files undeletable.
- **NOVABLIGHT_Disable_Task_Manager_via_Registry** (sigma, high): This rule detects a specific registry modification to disable the Task Manager, a common defense evasion technique employed by NOVABLIGHT.
- **NOVABLIGHT_PowerShell_Antivirus_Discovery** (sigma, medium): This rule detects a specific PowerShell command combination for AV discovery, a common reconnaissance step for malware like NOVABLIGHT.
