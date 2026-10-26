# Tiflux

Source: https://www.huntress.com/blog/tiflux-rmm-install

Threat actors use malspam with service agreement lures to deliver malicious MSI installers for the Tiflux RMM. The malware establishes persistence by installing multiple RMMs (UltraVNC, Splashtop, ScreenConnect) and uses a vulnerable driver for potential privilege escalation. The ultimate goal is persistent remote access for system profiling and data theft.

- **MAL_Tiflux_Installer_Oct2026** (yara, medium): This rule detects Tiflux installers by keying on a unique hardcoded email address and C2 domain.
- **Tiflux_PuTTY_Host_Key_Creation** (sigma, high): This rule keys on a highly specific PuTTY SSH host key registry value created by Tiflux, which includes a C2 domain.
- **Tiflux_RMM_Service_Creation** (sigma, high): This rule keys on the specific and unique service name 'TiService' created by Tiflux for persistence.
- **Tiflux_TightVNC_Service_Execution** (sigma, high): This rule keys on the specific installation path 'C:\PeopleOne\' used by Tiflux for its bundled TightVNC component.
- **Tiflux_C2_And_Payload_Domains** (sigma, high): This rule keys on a list of domains and TLDs specifically used by Tiflux for C2 and payload delivery.
- **Tiflux_C2_IP_Address** (sigma, high): This rule keys on a known C2 IP address used by Tiflux infrastructure for downloading components like ScreenConnect.
- **Tiflux_Vulnerable_Driver_Drop** (sigma, medium): This rule keys on the specific filename 'HwRwDrv.x64' being written to a temporary user or system folder.
