# BLOODALCHEMY

Source: https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/

VAPOR PANDA utilizes the ARTEX AI framework to automate and scale espionage campaigns against a wide range of global sectors. The actor deploys the BLOODALCHEMY backdoor, which is side-loaded via a renamed legitimate executable, and uses AI agents to discover unprotected endpoints and conduct lateral movement across cloud and on-premise environments.

- **APT_VAPOR_PANDA_BLOODALCHEMY_Oct2026** (yara, medium): This rule keys on highly specific PDB paths, filenames, and command strings from the VAPOR PANDA threat profile, which are unlikely to appear in legitimate software. All strings are derived from prose and are unverified.
- **VaporPandaBloodalchemySideloading** (sigma, high): This rule detects the specific BLOODALCHEMY DLL being side-loaded by a masquerading svchost.exe process, a high-fidelity combination of TTPs.
- **VaporPandaBloodalchemyMasqueradingProcess** (sigma, high): The execution path 'C:\ProgramData\artx5v\svchost.exe' is highly specific to the VAPOR PANDA ARTEX framework and is not a legitimate location for svchost.exe.
- **VaporPandaBloodalchemyLoaderFileCreation** (sigma, high): The combination of the specific file path 'C:\ProgramData\artx5v\' and filename 'graphics-hook-filter64.dll' is a strong indicator of compromise for VAPOR PANDA.
- **VaporPandaBloodalchemyC2Domains** (sigma, high): This rule keys on a list of C2 domains ('nginxmysql.com', 'sqlserver-sqlite.com', 'ddduuuppp.com') specifically associated with VAPOR PANDA's BLOODALCHEMY malware.
- **VaporPandaBloodalchemyC2Ips** (sigma, high): This rule keys on a list of C2 IP addresses specifically associated with VAPOR PANDA's BLOODALCHEMY malware infrastructure.
