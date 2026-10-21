# Linux Rootkits (Survey)

Source: https://www.elastic.co/security-labs/threat-command/linux-rootkits-2-caught-in-the-act

This report provides a survey of Linux rootkit techniques, emphasizing behavioral detection over fragile static signatures. It details userland (LD_PRELOAD) and kernel-space (LKM, eBPF, io_uring) infection and persistence mechanisms. Specific detection strategies are offered for process activity, file modifications, syscalls, and common defense evasion tactics like process masquerading and log clearing.

- **HKTL_Linux_Reptile_Udev_Persistence_Oct2026** (yara, high): This rule keys on a highly specific udev persistence rule string unique to the Reptile rootkit.
- **Linux_Kthreadd_Spawning_Shell** (sigma, high): This rule detects an extremely anomalous parent-child process relationship (`kthreadd` spawning a shell) which is a strong indicator of a compromised kernel.
- **Linux_Reptile_Rootkit_Loader_Execution** (sigma, high): This rule keys on the specific, hardcoded execution path `/lib/udev/reptile` used by the Reptile rootkit.
- **Linux_Singularity_Rootkit_Persistence_File** (sigma, high): This rule detects the creation of a highly specific persistence file, `singularity.conf`, in a standard module-loading directory.
- **Linux_BDS_Rootkit_Loader_Execution** (sigma, high): This rule combines a specific script name (`bds_start.sh`) and path (`/opt/bds_elf/`) associated with the BDS rootkit loader.
- **Linux_High_Signal_Number_With_Kill** (sigma, medium): This rule detects the use of the `kill` command with a specific, non-standard high signal number, a technique for covert triggers.
