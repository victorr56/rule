# KANDYKORN

Source: https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn

KANDYKORN is a memory-resident RAT used by the Lazarus Group in targeted attacks against blockchain engineers on macOS. Delivered via a multi-stage Python dropper, it uses reflective loading for evasion and features capabilities for system enumeration, file transfer, and remote command execution via an encrypted C2 channel. The malware establishes persistence by hijacking the legitimate Discord application.

- **APT_Lazarus_KANDYKORN_HLoader_Oct2026** (yara, high): This rule targets the HLOADER component of KANDYKORN using a unique adhoc identifier found in the binary, making it a high-confidence signature.
- **APT_Lazarus_KANDYKORN_RAT_Oct2026** (yara, medium): This rule detects the KANDYKORN RAT by matching a combination of internal command strings and C2-related artifacts, providing robust detection for the final payload.
- **APT_Lazarus_KANDYKORN_SugarLoader_Oct2026** (yara, medium): This rule detects the SUGARLOADER component by combining its use of a specific Mach-O constructor section, reflective loading indicators, and C2-related artifacts.
- **KandykornPersistenceViaDiscordHijack** (sigma, high): This rule detects a specific process lineage where a malicious loader masquerading as "Discord" launches the ".log" payload, a core KANDYKORN behavior.
- **KandykornInMemoryLoadingArtifact** (sigma, high): This rule keys on a highly specific temporary file pattern created by an API call used for KANDYKORN's reflective loading, making it a reliable indicator.
- **KandykornSugarloaderExecution** (sigma, high): This rule detects the execution of a specific hidden file (".sld") with an IP address as an argument, a combination highly indicative of the SUGARLOADER component.
- **KandykornConfigFileCreation** (sigma, high): This rule detects the creation of a file at a very specific path used by KANDYKORN for its configuration, which masquerades as a Safari cache file.
- **KandykornFinderToolsDropper** (sigma, medium): This rule detects the execution of a Python script named "FinderTools" which also contains "http://" in its command line, matching the dropper's behavior.
- **KandykornC2Domains** (sigma, high): This rule detects DNS queries for a list of domains specifically associated with the KANDYKORN campaign and wider Lazarus Group activity.
