# HwAudKiller

Source: https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill

An operator uses malvertising to deliver rogue ScreenConnect installers for initial access. A multi-stage crypter, 'FatMalloc', allocates 2GB of memory to evade sandboxes before unpacking 'HwAudKiller', a BYOVD tool. HwAudKiller abuses a legitimate, signed Huawei kernel driver to terminate EDR and antivirus processes from kernel mode, enabling credential theft and lateral movement.

- **HwAudKiller_Driver_Communication_Device_Path** (sigma, high): This rule keys on the unique device path `\\.\HWAudioX64` used by the malware's userland component, which is highly specific.
- **HwAudKiller_Kernel_Service_Creation** (sigma, high): This rule detects the specific command line for creating the malicious `Havoc` kernel service, a core TTP of this threat.
- **HwAudKiller_Dropped_Driver_Havoc_sys** (sigma, medium): This rule detects the creation of the uniquely named driver `Havoc.sys` in a temp path, a key step in the malware's setup.
- **LSASS_Memory_Dump_via_comsvcs_dll** (sigma, high): This rule keys on a specific `rundll32.exe` command line used to dump LSASS, combining the DLL, ordinal, and argument.
- **HwAudKiller_Kernel_Service_Registry_Key** (sigma, high): This rule detects the registry artifacts of the `Havoc` kernel service creation, a specific behavior of HwAudKiller.
- **HwAudKiller_Malvertising_And_C2_Domains** (sigma, high): This rule detects queries for attacker-owned domains used for payload delivery and C2, providing an early detection opportunity.
