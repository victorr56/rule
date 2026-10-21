# MIMICRAT

Source: https://www.elastic.co/security-labs/threat-command/mimicrat-custom-rat-mimics-c2-frameworks

MIMICRAT is a custom C++ RAT delivered via compromised websites using a multi-stage PowerShell and Lua loader chain. The malware features malleable C2 profiles mimicking legitimate web traffic, token impersonation, and SOCKS5 proxying. Its loader chain employs several defense evasion techniques, including ETW and AMSI bypasses, before executing the final implant entirely in memory.

- **MAL_MIMICRAT_Beacon_Oct2026** (yara, high): This rule detects the MIMICRAT beacon PE via a unique 128-byte RC4 key or a combination of specific C2 strings.
- **MAL_MIMICRAT_Loader_Oct2026** (yara, high): This rule detects the MIMICRAT PowerShell loader via its unique deobfuscation seed or a combination of a C2 domain and a bypass-related string.
- **MIMICRAT_PowerShell_Loader_Execution** (sigma, high): This rule keys on a unique, highly obfuscated PowerShell command line string used by the MIMICRAT loader.
- **MIMICRAT_Lua_Loader_Execution_zbuild** (sigma, high): This rule keys on the specific loader filename (`zbuild.exe`) executing from its characteristic staging directory pattern (`C:\ProgramData\knz_`).
- **MIMICRAT_Lua_Loader_Staged** (sigma, medium): This rule detects the staging of the `zbuild.exe` payload into the specific `C:\ProgramData\knz_` directory pattern used by MIMICRAT.
- **MIMICRAT_C2_DNS_Query** (sigma, high): This rule keys on DNS queries for known MIMICRAT C2 domains.
- **MIMICRAT_C2_IP_Connection** (sigma, high): This rule keys on network connections to known MIMICRAT C2 IP addresses.
