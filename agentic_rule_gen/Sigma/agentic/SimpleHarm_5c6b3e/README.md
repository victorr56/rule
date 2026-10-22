# SimpleHarm

Source: https://www.group-ib.com/blog/muddywater-infrastructure/

MuddyWater uses the legitimate remote administration tool SimpleHelp for persistence and control, delivered via lures such as archives containing malicious shortcuts. The actor's C2 infrastructure is fingerprinted by specific ETag hashes and shared SSH keys, and also includes custom Cobalt Strike configurations and PowerShell backdoors.

- **ProcCreationMuddywaterCurlVbs** (sigma, high): This rule detects a highly specific command line combining curl download, redirection to ProgramData, a decoy message, and VBS execution, as seen in MuddyWater TTPs.
- **ProcCreationMuddywaterVbsFromProgramdata** (sigma, medium): This rule detects VBS script execution from the C:\ProgramData directory, an uncommon location for user-initiated scripts and a known MuddyWater TTP.
- **FileEventMuddywaterPayloadDrop** (sigma, medium): This rule detects the suspicious combination of curl.exe creating a VBS file specifically in the C:\ProgramData directory, a known MuddyWater technique.
- **NetConnectionMuddywaterC2Ips** (sigma, high): This rule keys on a list of IP addresses identified as MuddyWater C2 infrastructure at the time of reporting.
