# GhostContainer

Source: https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/

NightEagle (APT-Q-95) gained access to Russian organizations via compromised VPN credentials and deployed the .NET GhostContainer backdoor on Microsoft Exchange servers by abusing VIEWSTATE and the x-owa-urlpostdata header. The group then tunnelled traffic with legitimate Microsoft dev tunnels (*.*.devtunnels.ms) and the public rdp2tcp tool over RDP, and moved laterally via Impacket atexec, portproxy, BlueKeep (CVE-2019-0708) exploitation and DCSync.

- **APT_NightEagle_GhostContainer_dotNET_Oct2026** (yara, high): This rule keys on unique hex patterns and C2 domains from GhostContainer, providing high-confidence detection.
- **NightEagleUserCreation** (sigma, high): This rule keys on a highly specific command line, including the username 'bosch' and hardcoded password 'Ktk17362', used by NightEagle for user creation.
- **GhostContainerDLLDrop** (sigma, high): This rule keys on two highly specific DLL filenames, 'App_Web_Container_1.dll' and a hash-based name, directly associated with the GhostContainer backdoor.
- **SuspiciousDevTunnelsHeader** (sigma, high): This rule combines a unique, suspicious HTTP header 'X-TunnelSkipAntiPhishingPage' with connections to the abused 'devtunnels.ms' domain for high precision.
- **SuspiciousDevTunnelsUsage** (sigma, medium): This rule detects DNS queries for '*.devtunnels.ms', a legitimate Microsoft service that is also frequently abused by threat actors for C2 tunneling.
- **ImpacketStExecExecution** (sigma, medium): This rule detects the execution of a python interpreter with 'stexec.py' in the command line, an indicator for a specific Impacket-based script.
