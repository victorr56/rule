# PARALLAX

Source: https://www.elastic.co/security-labs/threat-command/exploring-the-ref2731-intrusion-set

REF2731 uses the PARALLAX loader in maldoc campaigns to deliver the NETWIRE RAT. The loader chain begins with a macro downloading components for DLL side-loading via a legitimate Microsoft binary (MsiDb.exe). It uses steganography in PNG files and direct syscalls for process injection to evade detection, with persistence established via a scheduled task.

- **APT_REF2731_PARALLAX_Loader_Oct2026** (yara, high): This rule detects the PARALLAX loader DLL using unique code sequences, distinctive strings, and combinations of filenames and API strings.
- **REF2731_PARALLAX_Persistence_Msidb_Task** (sigma, high): This rule detects the specific command line used to create a persistence scheduled task, making it a high-fidelity indicator of this threat.
- **REF2731_PARALLAX_SideLoading_ImageLoad** (sigma, high): This rule keys on a legitimate process loading a specific DLL from a non-system path, a classic and high-fidelity side-loading TTP.
- **REF2731_PARALLAX_SideLoading_Process_Creation** (sigma, medium): This rule detects the `MsiDb.exe` process executing from outside its legitimate system directories, indicating it has been staged for abuse.
- **REF2731_NETWIRE_C2_Domains** (sigma, high): This rule detects queries to a list of domains exclusively controlled by the threat actor for C2 and payload delivery.
