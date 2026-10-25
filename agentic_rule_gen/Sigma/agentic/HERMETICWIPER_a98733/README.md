# HERMETICWIPER

Source: https://www.elastic.co/security-labs/threat-command/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper

HERMETICWIPER is a data wiper malware observed in attacks against Ukrainian organizations. It leverages a legitimate, signed driver from EaseUS Partition Manager to gain raw disk access for destructive operations. The malware corrupts file data, partition information, and the boot sector to render systems unbootable.

- **MAL_HERMETICWIPER_Wiper_Oct2026** (yara, medium): This rule keys on the unique PDB path `tdrv.pdb` and the signer-related string `Hermetica Digital`, which are strong indicators for HERMETICWIPER.
- **HERMETICWIPER_Service_Creation_For_Abused_EaseUS_Driver** (sigma, high): This rule detects the specific command line used by HERMETICWIPER to create a service for the abused EaseUS driver, a core part of its execution chain.
- **Suspicious_Load_of_EaseUS_Driver** (sigma, medium): This rule detects the loading of the abused `epmntdrv.sys` driver by any process except known legitimate EaseUS software, a key tactic of HERMETICWIPER.
- **HERMETICWIPER_Disabling_Explorer_Visual_Cues** (sigma, medium): This rule detects specific registry changes made by HERMETICWIPER to hide its presence, providing a medium-confidence signal of defensive evasion.
