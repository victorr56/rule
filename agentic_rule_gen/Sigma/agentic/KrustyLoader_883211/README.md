# KrustyLoader

Source: https://www.darktrace.com/blog/tracking-cve-2025-31324-darktraces-detection-of-sap-netweaver-exploitation-before-and-after-disclosure

KrustyLoader is an initial-stage loader associated with the Chinese threat actor UNC5221, often delivered after exploiting vulnerabilities like CVE-2025-31324 in SAP NetWeaver. The malware downloads a second-stage C2 payload, such as Sliver, and then removes itself to evade detection. Attackers have also been observed downloading privilege escalation tools like JuicyPotato as part of the same activity.

- **UNC5221_SAP_NetWeaver_Exploitation_CVE_2025_31324** (sigma, high): This rule detects the highly specific URI path used in the CVE-2025-31324 exploit.
- **KrustyLoader_JuicyPotato_Download_Network** (sigma, high): This rule combines a known attacker IP with an unusual destination port for high-fidelity detection.
- **UNC5221_JuicyPotato_Download_URI** (sigma, medium): This rule keys on the combination of a specific folder path and filename in a URL.
- **OAST_Domain_Query** (sigma, medium): This rule detects DNS queries for OAST domains used to confirm exploits, as seen in UNC5221 activity.
