# SPECTRALVIPER

Source: https://www.elastic.co/security-labs/threat-command/elastic-charms-spectralviper

SPECTRALVIPER is a heavily obfuscated 64-bit C++ backdoor attributed to the Vietnamese threat actor APT32/Canvas Cyclone. It supports PE injection, file manipulation, and token impersonation, communicating via HTTP or a named pipe. It is often deployed alongside the P8LOADER PE loader and the POWERSEAL PowerShell runner.

- **APT_CanvasCyclone_SPECTRALVIPER_Backdoor_Oct2026** (yara, high): The rule uses highly specific code patterns, a unique AES key, and high-entropy named pipes.
- **APT_CanvasCyclone_P8LOADER_Loader_Oct2026** (yara, medium): The rule keys on a combination of specific debug and format strings found in the P8LOADER component.
- **APT_CanvasCyclone_POWERSEAL_Runner_Oct2026** (yara, medium): The rule detects the .NET POWERSEAL tool by combining specific user strings and error messages.
- **CanvasCycloneSpectralViperPowerShellLoader** (sigma, high): This rule keys on a highly specific PowerShell loop structure and arguments used to find and execute a SPECTRALVIPER DLL export.
- **CanvasCycloneSpectralViperSideloading** (sigma, high): This rule detects a specific DLL side-loading pattern by matching `nslookup.exe` loading `dnsapi.dll` from outside legitimate system paths.
- **CanvasCycloneSpectralViperC2Domains** (sigma, high): This rule keys on a list of DNS queries for domains known to be used exclusively by SPECTRALVIPER C2 servers.
