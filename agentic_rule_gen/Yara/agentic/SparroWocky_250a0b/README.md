# SparroWocky

Source: https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/

SparroWocky is the modular C++ backdoor that replaced SparrowDoor as FamousSparrow's flagship implant, deployed since at least August 2025 against governmental targets in Latin America. It is delivered by a trident loader (legitimate EXE plus side-loaded malicious DLL) that RC4-decrypts a .dat payload, uses TLS with RC4-encrypted command data over IP-based C2, and persists via a Windows service or a Run key. The backdoor supports command execution, in-memory PE and BOF loading, TCP proxying, screenshots and file exfiltration, with heavy anti-analysis (SilentMoonwalk, API hashing, LDR forging).

- **APT_FamousSparrow_SparroWocky_Backdoor_Oct2026** (yara, medium): This rule keys on unique strings and constants from the SparroWocky backdoor, including a service description, a crypto personalization string, and other specific values.
- **sparrowocky_service_persistence** (sigma, high): This rule detects the creation of a Windows service with a name specific to SparroWocky.
- **sparrowocky_run_key_persistence** (sigma, high): This rule detects a Run key persistence mechanism using a value name, 'SnapCart', specific to SparroWocky.
- **sparrowocky_service_execution** (sigma, high): This rule detects SparroWocky's specific execution pattern when started as a service.
- **sparrowocky_self_deletion** (sigma, medium): This rule detects the command-line pattern for SparroWocky's self-deletion mechanism.
- **sparrowocky_c2_traffic** (sigma, high): This rule detects network connections to a list of IP addresses known to be SparroWocky C2 servers.
