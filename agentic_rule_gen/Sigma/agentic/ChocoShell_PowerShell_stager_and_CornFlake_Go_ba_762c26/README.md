# ChocoShell (PowerShell stager) and CornFlake (Go backdoor) — GTG-20006 / CaptiveCrunch cluster

Source: https://www.reversinglabs.com/blog/how-rl-mapped-a-midnight-blizzard-linked-campaign-from-two-hashes

A Midnight Blizzard-linked espionage cluster (GTG-20006 / Storm-2945) delivers ChocoShell, a PowerShell stager, and CornFlake, a Go backdoor, after Microsoft 365 device-code phishing and click-through Internet Shortcut lures. The stager hides its window, decodes Base64, collects browser history with PowerSploit/Empire code and beacons over HTTPS to a raw IP on /t/pixel.gif with operator-chosen stage labels, exfiltrating to /t/event. The Go backdoor persists as svchost32.exe from a fake LocalAppData\Microsoft\svchost32 folder via an HKCU Run value and a Schedule.Service COM object, then injects into a suspended process and harvests browser and Teams data.

- **APT_MidnightBlizzard_CornFlake_Backdoor_Oct2026** (yara, high): This rule detects the CornFlake Go backdoor using two unique marker filenames found in the binary. An alternative, more resilient condition requires one unique marker and two supporting strings from the binary, including prose-sourced values.
- **MidnightBlizzard_CornFlake_Execution_Path** (sigma, high): This rule keys on the highly specific installation path of the CornFlake backdoor, making it a high-confidence indicator of compromise.
- **MidnightBlizzard_CornFlake_Persistence_RunKey** (sigma, high): This rule precisely targets the registry persistence mechanism by combining a standard autorun location with the backdoor's specific file path.
- **MidnightBlizzard_ChocoShell_C2_Beacon** (sigma, high): This rule detects the unique URI path and parameter structure of the ChocoShell stager's C2 communication, which is a strong behavioral indicator.
- **MidnightBlizzard_CornFlake_Service_Creation** (sigma, high): This rule correlates the use of `sc.exe` with the specific service name, binary path, and display name associated with CornFlake persistence.
- **MidnightBlizzard_CaptiveCrunch_Phishing_C2_Domains** (sigma, medium): This rule provides coverage for known C2 and phishing domains from the threat profile, useful for identifying initial and ongoing communications.
- **MidnightBlizzard_CaptiveCrunch_C2_Staging_IPs** (sigma, medium): This rule provides coverage for known C2 and staging IP addresses from the threat profile, useful for identifying direct network connections.
