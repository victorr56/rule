# DYNOWIPER

Source: https://www.elastic.co/security-labs/blog/dynowiper

DYNOWIPER is a destructive wiper attributed to Static Tundra (Berserk Bear) used against Poland's energy sector. The malware is a standalone executable with no C2 or persistence, designed for rapid data destruction. It enumerates fixed and removable drives, corrupts files by overwriting their headers with random data, and forces a system reboot upon completion.

- **StaticTundra_DYNOWIPER_Distribution_Script** (sigma, high): This rule detects the specific and unique PowerShell script name `dynacon_update.ps1` used to distribute DYNOWIPER.
- **StaticTundra_DYNOWIPER_C2_IPs** (sigma, high): This rule detects connections to a list of IP addresses specifically linked to the DYNOWIPER campaign infrastructure.
