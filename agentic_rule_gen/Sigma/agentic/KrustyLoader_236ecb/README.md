# KrustyLoader

Source: https://www.darktrace.com/blog/ivanti-under-siege-investigating-the-ivanti-endpoint-manager-mobile-vulnerabilities-cve-2025-4427-cve-2025-4428

Exploitation of the chained Ivanti Endpoint Manager Mobile vulnerabilities CVE-2025-4427 and CVE-2025-4428 gives unauthenticated attackers remote code execution and was observed delivering KrustyLoader ELF payloads, activity that suggests the suspected China-nexus espionage actor UNC5221. Post-exploitation behaviour included OAST-based exploit validation, payload hosting on AWS S3 bucket endpoints, retrieval of a randomly named .sh payload from an IP linked to SAP NetWeaver CVE-2025-31324 infrastructure, and connections to pastebin[.]com and dpaste[.]com for dynamic payload retrieval.

- **APT_UNC5221_DiscordRAT_Oct2026** (yara, high): The rule keys on a highly unique Discord bot token and channel ID, or a combination of the Discord API URL and command prefixes, providing strong detection for the described RAT.
- **APT_UNC5221_EdgeSideload_Oct2026** (yara, medium): The rule detects a tool by combining file paths specific to a dbghelp.dll sideloading technique against Microsoft Edge, making it a targeted and likely precise detector.
- **UNC5221_C2_URL_TIGHT_UNIVERSITY** (sigma, high): This rule detects a highly specific and unique C2 URL component ('TIGHT_UNIVERSITY') combined with the C2 IP address, making it a critical and high-confidence indicator of compromise.
- **Linux_UNC5221_cURL_PayloadDownload** (sigma, high): This rule combines a generic Linux utility (`curl`) with specific attacker C2 IPs and domains in the command line, providing a high-fidelity behavioral detection for payload retrieval.
- **Net_UNC5221_C2_Domains** (sigma, high): This rule detects DNS lookups for a list of domains specifically created and used by the actor for C2, making it a reliable network indicator.
- **Linux_UNC5221_Root_Payload_Drop** (sigma, medium): This rule detects a highly suspicious file creation pattern (a short, random-looking filename in the root directory) that matches observed actor TTPs, serving as a valuable threat hunting lead.
