# LOBSHOT

Source: https://www.elastic.co/security-labs/threat-command/elastic-security-labs-discovers-lobshot-malware

LOBSHOT is an hVNC malware used for financial theft, featuring info-stealing and banking trojan capabilities. Attributed to the cybercrime group TA505, it is distributed via malvertising campaigns and uses a hidden desktop for unobserved remote access, registry keys for persistence, and dynamic API resolution to evade detection.

- **MAL_LOBSHOT_Oct2026** (yara, medium): The rule keys on unique internal strings from LOBSHOT and combines them with weaker but specific indicators like anti-emulation strings and an infection marker. The condition requires either one strong unique string or four supporting strings, ensuring high precision.
- **LobshotModuleExecution** (sigma, high): This rule keys on a highly specific command line used by LOBSHOT to execute its downloaded modules via rundll32.
- **LobshotInfectionMarkerRegistryWrite** (sigma, high): This rule detects a highly specific registry value written to an unusual key, serving as a unique LOBSHOT infection marker.
- **LobshotSelfDeletionCommand** (sigma, medium): This rule detects the specific self-deletion command pattern used by LOBSHOT, combining a ping delay with a del command.
- **LobshotModuleDrop** (sigma, medium): This rule detects the creation of files matching LOBSHOT's specific `hmr_*.dat` naming convention in the `C:\ProgramData` directory.
