# BPFDoor

Source: https://www.elastic.co/security-labs/threat-command/a-peek-behind-the-bpfdoor

BPFDoor is a passive Linux backdoor used for long-term persistence, attributed to Red Menshen. It uses a Berkeley Packet Filter (BPF) to stealthily monitor network traffic for a magic packet, which activates a reverse or bind shell. The malware employs various anti-forensic techniques, such as process name spoofing and placing itself in temporary filesystems like /dev/shm.

- **APT_RedMenshen_BPFDoor_Linux_Oct2026** (yara, high): The rule keys on highly specific BPFDoor artifacts: a unique BPF filter string, a debug message with a typo, specific error messages, unique code patterns, and combinations of process masquerading strings.
- **Linux_BPFDoor_Execution_From_Dev_Shm** (sigma, high): This rule detects BPFDoor execution via its unique hardcoded name and path, which is a critical indicator.
- **Linux_BPFDoor_BPF_Filter_String** (sigma, high): This rule detects a unique, hardcoded BPF filter string in a command line, a critical indicator for BPFDoor's activation mechanism.
- **Linux_BPFDoor_Iptables_Rule_Deletion** (sigma, high): This rule detects a highly specific `iptables` command line pattern used by BPFDoor to manipulate network rules.
- **Linux_BPFDoor_Process_Initialization** (sigma, medium): This rule combines the unique BPFDoor process name `kdmtmpflush` with its specific `-init` argument for high-fidelity detection.
