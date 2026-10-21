# NOX Stealer (rebranded BOMBAY Stealer)

Source: https://blog.virustotal.com/2026/10/internet-scanning-in-vt.html

VirusTotal's Internet Scanning data exposes per-port service banners, products/versions, CPEs and SSH/RDP fingerprints for the public IPv4 space, enabling pivots on rare host keys, certificate subjects and service stacks. The post shows the technique unmasking a NOX/BOMBAY Stealer operator login panel on 5.175.221.206:8443 hosted on a Windows Server 2022 host with SMB/RDP exposed, and hunting FTP-banner dead drop resolvers that pipe a banner-embedded 'ftp <ip>|powershell' command into a shell. Detection value lies in the service banners, panel strings and multi-port host signatures rather than in raw open ports.

- **WEBSHELL_NOX_Stealer_Panel_Oct2026** (yara, low): The rule keys on weak, prose-sourced strings from the NOX/BOMBAY Stealer C2 panel's web assets, requiring all to match for precision.
- **NoxStealerFtpBannerExecution** (sigma, high): This rule keys on a highly specific and unusual command line execution chain involving conhost, ftp, and powershell.
- **FtpBannerExecutionViaShellPipe** (sigma, medium): This rule detects the generic TTP of piping FTP output to a shell, a suspicious pattern used for dead-drop C2.
- **NoxStealerAssociatedDomains** (sigma, high): This rule detects DNS queries for domains specifically identified with NOX Stealer C2 infrastructure.
- **NoxStealerAssociatedIps** (sigma, high): This rule detects network connections to a list of IPs identified as NOX Stealer C2 or dead-drop infrastructure.
