# SHELLTER

Source: https://www.elastic.co/security-labs/threat-command/taking-shellter

SHELLTER is a commercial evasion framework (Shellter Elite v11.0) observed being used by multiple infostealer campaigns since April 2025. It employs advanced techniques including API hashing from time-based seeds, indirect syscalls, unhooking ntdll.dll, and Vectored Exception Handler (VEH) based API proxying to evade detection. A consistent license expiry timestamp across samples suggests a single illicitly obtained copy is in use.

- **HKTL_SHELLTER_Framework_Oct2026** (yara, medium): The rule keys on strong unique indicators for SHELLTER, including a hardcoded CLSID, configuration strings, and code patterns.
- **SHELLTER_Typo_DLL_Load** (sigma, high): This behavioral rule keys on the highly specific and unusual typo'd DLL filenames `kern3l32.dll` and `ntll.dll` used by SHELLTER.
- **SHELLTER_C2_Domains** (sigma, high): This rule keys on a C2 domain (`eaglekl.digital`) explicitly linked to a SHELLTER-involved campaign with Lumma Stealer.
- **SHELLTER_C2_IPs** (sigma, high): This rule keys on C2 IP addresses explicitly linked to SHELLTER-involved campaigns with ARECHCLIENT2 and Rhadamanthys.
