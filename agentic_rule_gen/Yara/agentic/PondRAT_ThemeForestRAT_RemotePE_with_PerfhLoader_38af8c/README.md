# PondRAT, ThemeForestRAT, RemotePE (with PerfhLoader, DPAPILoader, RemotePELoader)

Source: https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/

Fox-IT and NCC Group describe a financially motivated Lazarus subgroup that uses social engineering against cryptocurrency and DeFi organisations and deploys three RATs: PondRAT, ThemeForestRAT and RemotePE. Persistence is achieved through phantom DLL loading of a custom PerfhLoader via the SessionEnv (or IKEEXT) service, and the actor layers custom and public tooling such as keyloggers, a Chromium credential dumper, Proxymini, frpc and Mimikatz. PondRAT is a simple HTTP(S) RAT with XOR+Base64 messaging, ThemeForestRAT is a stealthier in-memory second stage with an RC4-encrypted configuration file, and RemotePE is a DPAPI-keyed, later-stage RAT on three platforms.

- **APT_Lazarus_PondRAT_Oct2026** (yara, high): This rule detects PondRAT using its hardcoded 64-character hex XOR key, a unique User-Agent string, and specific command format strings and C2 parameters for all targeted platforms.
- **APT_Lazarus_RemotePE_Loader_Oct2026** (yara, high): This rule detects RemotePE and its loader using a unique User-Agent string (`Microsoft-Delivery-Optimization/10.0`) and several distinctive class and C2 parameter names.
- **APT_Lazarus_DPAPILoader_Oct2026** (yara, high): This rule provides high-confidence detection for DPAPILoader by searching for unique error messages, one of which contains a distinctive typo ("out ouf bounds").
- **LazarusSessionEnvPrivilegeModification** (sigma, high): This rule detects a highly specific registry modification used by the actor to prepare for phantom DLL loading.
- **LazarusPerfhLoaderPhantomDLLCreation** (sigma, high): This rule detects the file creation of specific, non-standard DLLs in System32 used for phantom DLL loading.
- **LazarusSessionEnvServicePersistenceConfiguration** (sigma, medium): This rule detects a specific command line used by the actor to establish persistence for their phantom DLL loader.
- **LazarusSubgroupC2DomainQuery** (sigma, high): This rule detects DNS queries to a list of domains exclusively used by the Lazarus subgroup for C2 infrastructure.
- **PotentialLazarusGroupFRPExecution** (sigma, medium): This rule detects the specific filenames and command-line arguments used by the actor to run the FRP tool.
