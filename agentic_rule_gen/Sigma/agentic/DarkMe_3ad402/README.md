# DarkMe

Source: https://www.huntress.com/blog/darkme-rat-abandons-exploits

DarkMe is a Visual Basic 6 spy-RAT attributed to Water Hydra (EvilNum/Operation DarkCasino) that in this campaign dropped zero-days in favour of an email-delivered image.pif that fetches a remote exemsi-wrapped MSI. The MSI expands a CAB into %AppData%\ComponentsFolder, runs prnfig.wsf to register a COM object and a custom Locked:// protocol handler, then loads three VB6 loader DLLs that gate on 329 user applications and hollow Microsoft-signed clspack.exe. The injected RAT profiles the host, steals crypto wallets and screenshots, and beacons over a custom TCP channel on port 7712 to an RC4-encrypted C2 domain.

- **APT_WaterHydra_DarkMe_Loader_Oct2026** (yara, high): This rule detects the DarkMe loader DLLs using a strong PDB path, decryption keys, and unique project names.
- **APT_WaterHydra_DarkMe_Payload_Oct2026** (yara, high): This rule detects the core DarkMe payload via its unique internal project names and hardcoded C2 domain.
- **APT_WaterHydra_DarkMe_Dropper_Oct2026** (yara, medium): This rule detects the DarkMe dropper by specific, forged product and filename strings in its version information.
- **DarkMePersistenceViaCustomURLProtocol** (sigma, high): This rule detects the specific registry write that creates the 'Locked' protocol handler command, a unique persistence mechanism for DarkMe.
- **DarkMePersistenceViaRunKey** (sigma, high): This rule detects the specific 'Locked' Run key and its command, which is the trigger for DarkMe's custom protocol handler persistence.
- **DarkMeStagingCommandLine** (sigma, high): This rule detects a highly specific command line combination executed by wscript.exe, a core part of the DarkMe execution chain.
- **DarkMeInitialAccessViaRemoteMSI** (sigma, high): This rule detects the remote installation of a specific MSI file (`propi.msi`) via msiexec, characteristic of DarkMe's initial staging.
- **DarkMeC2AndStagingDomains** (sigma, high): This rule detects network lookups for a list of domains exclusively associated with the Water Hydra group's DarkMe operations.
