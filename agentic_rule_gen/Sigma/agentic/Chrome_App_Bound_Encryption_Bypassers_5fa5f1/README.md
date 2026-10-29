# Chrome App-Bound Encryption Bypassers

Source: https://www.elastic.co/security-labs/threat-command/katz-and-mouse-game

Multiple infostealer families, including STEALC, METASTEALER, PHEMEDRONE, XENOSTEALER, and LUMMA, have updated their TTPs to bypass Google Chrome's Application-Bound Encryption for cookie theft. Observed techniques include reimplementing the ChromeKatz tool for memory scanning, leveraging a Chrome COM service for decryption key access, and using the remote debugging protocol. These methods are noisy and present new detection opportunities for defenders.

- **Phemedrone_Off_Screen_Chrome_Launch** (sigma, high): This rule detects a highly specific and anomalous command-line argument used to launch Chrome far off-screen, as seen with Phemedrone.
- **Suspicious_Parent_Process_For_Chrome_Elevation_Service** (sigma, high): This rule detects the abuse of a legitimate Chrome component by identifying anomalous process parentage, a strong behavioral indicator.
- **Suspicious_Chrome_Network_Service_Argument_Usage** (sigma, high): This rule detects a highly specific and technical argument used by a non-Chrome process, indicating masquerading or other malicious activity.
- **Chrome_Remote_Debugging_Enabled** (sigma, medium): This rule detects a common technique for browser manipulation by infostealers; while it has legitimate uses, it's often abused by malware.
