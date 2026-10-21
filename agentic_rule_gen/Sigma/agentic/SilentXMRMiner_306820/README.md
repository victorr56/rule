# SilentXMRMiner

Source: https://www.huntress.com/blog/threat-actor-compiles-cryptominer

A threat actor exploited the Samsung MagicINFO vulnerability CVE-2025-4632 (via the Apache Tomcat service, tomcat9.exe) to install a rogue AnyDesk instance, create the local admin account 'oldadministrator', and disable Microsoft Defender. They then ran Silent XMR Miner Builder.exe on the endpoint, which spawned .NET and C compilers (csc.exe, cvtres.exe, donut.exe, tcc.exe, cc1.exe, gcc.exe) to compile a cryptominer that was injected into explorer.exe and mined Monero via the public C3Pool service.

- **MAL_SilentXMRMiner_Activity_Oct2026** (yara, medium): This rule keys on a unique password and a specific download URL, or a combination of supporting strings from the attack chain, for high-confidence detection of related tools.
- **SilentXMRMiner_Explorer_Injection** (sigma, high): This rule is highly precise as explorer.exe should never have command-line arguments associated with cryptocurrency miners; this is a clear sign of process injection.
- **SilentXMRMiner_AnyDesk_Unattended_Password** (sigma, high): This rule is precise because it combines a non-standard file path for AnyDesk (`C:\ProgramData\AnyDesk.exe`) with a command-line argument (`--set-password`) that establishes unattended access.
- **SilentXMRMiner_User_Creation** (sigma, high): This rule is precise because it detects the creation of a local account using the specific and unusual name 'oldadministrator' observed in this attack.
- **SilentXMRMiner_Builder_Activity** (sigma, high): This rule is precise because it keys on a specific malware tool (`Silent XMR Miner Builder.exe`) acting as the parent process for multiple compilers, a strong indicator of on-host malware compilation.
- **SilentXMRMiner_AnyDesk_Download** (sigma, medium): This rule detects the specific behavior of downloading `AnyDesk.exe` into the non-standard `C:\ProgramData` directory, a technique used by this actor for staging their remote access tool.
- **SilentXMRMiner_C2_IP** (sigma, high): This rule is a high-confidence indicator based on a network connection to an IP address (`194.87.89.30`) known to be used by the actor for malware staging.
