# RansomHub

Source: https://www.darktrace.com/blog/darktraces-cyber-ai-analyst-in-action-4-real-world-investigations-into-advanced-threat-actors

RansomHub gains initial access via VPN from a specific attacker device and moves laterally with RDP. The malware distributes payloads via SMB, exfiltrates data using HTTP POSTs to a hardcoded IP on port 5000, and encrypts files, appending the '.b2a830' extension and dropping a corresponding ransom note.

- **MAL_RansomHub_Gen_Oct2026** (yara, medium): This rule keys on a unique ransom note filename mentioned in the report, which is a strong indicator if present in the binary.
- **RansomHub_Exfiltration_C2** (sigma, high): This rule detects network connections to a specific IP and port combination (104.194.10.170:5000) used for RansomHub data exfiltration.
