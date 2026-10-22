# LapDogs ORB

Source: https://www.darktrace.com/blog/2025-cyber-threat-landscape-darktraces-mid-year-review

Campaign by Chinese-nexus actors exploiting internet-facing devices like Trimble Cityworks (CVE-2025-0994) to deliver payloads like z44.exe. The activity uses a C2 infrastructure called the LapDogs ORB network, which has used TLS certificates spoofing law enforcement.

- **LapDogs_ORB_Payload_Execution_From_IIS** (sigma, high): This rule keys on the specific parent-child process relationship (`w3wp.exe` spawning `z44.exe`), which is a strong indicator of post-exploitation activity via a web server.
- **LapDogs_ORB_Payload_Download_z44** (sigma, high): This rule is precise because it combines a specific IP address, a non-standard port, and a unique filename from a confirmed malware download URL.
- **LapDogs_ORB_ShortLeash_Payload_Download** (sigma, high): This rule is precise because it combines a specific IP address, a non-standard port, and a unique filename from a confirmed malware download URL.
- **LapDogs_ORB_C2_Domain** (sigma, high): This rule detects DNS queries for a domain confirmed to be part of the LapDogs ORB C2 infrastructure.
- **LapDogs_ORB_C2_IP_Connection** (sigma, high): This rule detects network connections to a list of IP addresses confirmed to be part of the LapDogs ORB C2 infrastructure.
