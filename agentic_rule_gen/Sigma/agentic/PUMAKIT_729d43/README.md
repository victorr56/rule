# PUMAKIT

Source: https://www.elastic.co/security-labs/threat-command/declawing-pumakit

PUMAKIT is a multi-stage Linux malware comprising a dropper, memory-resident modules, and a kernel rootkit named PUMA. It uses ftrace to hook syscalls for stealth, privilege escalation, and C2 communications. A key feature is its abuse of the rmdir syscall for command-and-control, such as retrieving its configuration or gaining root privileges.

- **MAL_PUMAKIT_Linux_Rootkit_Oct2026** (yara, high): This rule targets the PUMAKIT LKM rootkit using its unique `.puma-config` section name and specific strings from its C2 mechanism.
- **PUMAKIT_C2_via_rmdir** (sigma, high): This rule detects the unique PUMAKIT C2 mechanism combining the `rmdir` command with specific `zarya.*` arguments.
- **PUMAKIT_Rootkit_Artifact_Manipulation** (sigma, high): This rule is precise because it keys on the `truncate` command combined with a highly specific file path used only by PUMAKIT.
- **PUMAKIT_Kernel_Mode_Execution_Anomaly** (sigma, medium): This rule detects an anomalous process lineage where a kernel thread (parent PID 2) spawns `truncate`, as seen with PUMAKIT.
- **PUMAKIT_C2_Domain_Query** (sigma, high): This rule is a high-confidence IOC rule that detects DNS queries for known PUMAKIT C2 domains.
- **PUMAKIT_C2_Connection** (sigma, high): This rule is a high-confidence IOC rule that detects network connections to a known PUMAKIT C2 IP address.
