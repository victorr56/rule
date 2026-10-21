# Qilin

Source: https://www.darktrace.com/blog/a-busy-agenda-darktraces-detection-of-qilin-ransomware-as-a-service-operator

Qilin is a Ransomware-as-a-Service (RaaS) written in Rust and Go, enabling cross-platform attacks. Affiliates, such as Pistachio Tempest, gain initial access via phishing or exploiting exposed services, then move laterally using RDP, WMI, and SCCM. The operators use tools like Cobalt Strike and SystemBC for C2 and exfiltrate data to services like MEGA or via FTP before encrypting files and dropping ransom notes.

- **APT_PistachioTempest_Qilin_Strings_Oct2026** (yara, high): This rule keys on a highly specific self-signed certificate subject and a file download path, both explicitly mentioned in the report as being used by the threat actor.
- **HKTL_CobaltStrike_PistachioTempest_URI_Oct2026** (yara, medium): This rule detects Cobalt Strike beacons configured with specific URI paths used by Pistachio Tempest. While the paths are from Cobalt Strike, their specific combination suggests this actor's configuration.
- **Qilin_Malware_PowerShell_Download_sihost64** (sigma, high): This rule detects a specific PowerShell command line used by Qilin operators to download a malicious DLL, combining the process image with specific command arguments for high precision.
- **Qilin_Malware_LSM_API_service_File_Creation** (sigma, high): This rule detects the creation of a file with the highly specific and unusual name "LSM_API_service", a key indicator of Qilin-related activity.
- **Cobalt_Strike_C2_URI_Associated_With_Qilin** (sigma, high): This rule detects specific and unusual URI paths used by Cobalt Strike C2, as observed in Qilin ransomware campaigns.
- **Qilin_C2_And_Exfiltration_IPs** (sigma, high): This rule detects network connections to a list of IP addresses known to be used for C2 and exfiltration by Qilin operators.
- **Cobalt_Strike_C2_Domain_Associated_With_Qilin** (sigma, high): This rule detects DNS queries for specific, attacker-controlled domains used as Cobalt Strike C2 infrastructure in Qilin campaigns.
