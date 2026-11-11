# Sparrow

Source: https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/

CopperDragon is a potential digital quartermaster supplying the Sparrow framework to multiple China-nexus threat actors. The cross-platform framework, with Windows (SparrowDoor) and Linux (SparrowShell) variants, is used in distinct campaigns utilizing different backdoors like SquadC and CopperDoor. Tactics include watering-hole attacks, DLL sideloading, and kernel-level components for espionage.

- **APT_CopperDragon_Sparrow_Framework_Nov2026** (yara, medium): This rule detects core Sparrow framework backdoors using highly specific strings like `SparroWocky` and a unique certificate organization, or a pair of magic constants.
- **APT_CopperDragon_Toolset_Nov2026** (yara, medium): This rule detects CopperDragon's wider toolset using specific lure filenames, hardcoded certificate fingerprints, or a combination of supporting strings like internal names, C2 paths, and component names.
- **CopperDragon_Hidden_Admin_Creation** (sigma, high): This rule detects a highly specific command line used by CopperDragon's tooling to create a hidden admin user.
- **CopperDragon_Firewall_Rule_For_SMB** (sigma, high): This rule detects a specific `netsh.exe` command line with the unique firewall rule name "RasiUwpApp", indicative of CopperDragon activity.
- **CopperDragon_SquadC_Persistence** (sigma, high): This rule detects the creation of a specific registry value ('WindowsUpdateAssist') in a common persistence location (Run key).
- **CopperDragon_DarkWire_VLC_Sideloading** (sigma, high): This rule detects a known DLL sideloading pattern (vlc.exe loading libvlccore.dll) while filtering for executions from non-default paths.
