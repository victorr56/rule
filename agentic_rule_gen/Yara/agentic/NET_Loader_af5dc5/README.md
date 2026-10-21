# .NET Loader

Source: https://www.huntress.com/blog/malspam-to-loader-delivery-chain-analysis

This threat profile describes a multi-stage, fileless .NET loader delivered via a malspam campaign. The loader employs in-memory execution, heavy obfuscation, and extensive anti-analysis and defense evasion techniques, including patching AMSI and ETW. It establishes persistence via scheduled tasks and registry keys and uses legitimate Microsoft binaries like InstallUtil.exe and MSBuild.exe for process injection.

- **MAL_NetLoader_Huntress_Oct2026** (yara, medium): This rule keys on a hardcoded TripleDES key, an obfuscated import name, and unique URL paths.
- **DotNETLoaderPersistenceRegistryKey** (sigma, high): This rule detects a highly specific registry value name prefix used for persistence.
- **DotNETLoaderStagingDirectory** (sigma, high): This rule detects file activity in a deeply nested and unusually repetitive directory path.
- **DotNETLoaderC2Domains** (sigma, high): This rule detects DNS queries to a list of actor-controlled C2 and payload domains.
- **DotNETLoaderAntiAnalysisMarkerFile** (sigma, high): This rule detects a highly specific marker filename, including a typo ("analisse").
- **DotNETLoaderDroppedScripts** (sigma, high): This rule detects specific script filenames created in an unusual public directory.
