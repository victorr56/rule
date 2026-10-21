# Lynx Ransomware

Source: https://www.darktrace.com/blog/new-threat-on-the-prowl-investigating-lynx-ransomware

Lynx is a Ransomware-as-a-Service (RaaS) that emerged in mid-2024, sharing significant source code with the INC ransomware variant. It employs a double extortion model, exfiltrating data to cloud storage like AWS S3 before encrypting files and appending the '.LYNX' extension. The group has been observed using compromised administrative credentials and legitimate remote access tools like AnyDesk for lateral movement.

- **LynxRansomwareFileEncryption** (sigma, high): This rule detects the file extension (.LYNX) appended by the ransomware, providing a high-confidence alert for an active infection.
- **SuspiciousAnyDeskRelayActivity** (sigma, medium): This rule keys on a list of specific AnyDesk relay hostnames observed being used by the Lynx ransomware group for C2 and lateral movement.
