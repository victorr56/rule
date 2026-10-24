# Diicot

Source: https://www.wiz.io/blog/diicot-threat-group-malware-campaign

Diicot is a malware targeting Linux systems, often in cloud environments, via weak SSH credentials. It spreads using a custom UPX-packed Go binary, maintains persistence with cron jobs, and exfiltrates data to an HTTP C2. In non-cloud environments, it deploys an XMRig-based cryptominer.

- **MAL_Diicot_Linux_Oct2026** (yara, medium): The rule keys on highly specific strings found in Diicot malware, including a unique Romanian error message, hardcoded cloud kernel versions, and C2 paths. The condition requires either one strong anchor or a combination of several characteristic but weaker strings to ensure precision.
- **Linux_Diicot_Curl_Bash_Persistence** (sigma, high): This rule detects a highly specific curl-to-bash command, a strong indicator of Diicot's persistence mechanism.
- **Linux_Diicot_Remove_File_Attributes** (sigma, high): This rule keys on a specific `chattr` command line used by Diicot for defense evasion, combining the tool with its specific arguments and target file path.
- **Linux_Diicot_Payload_Drop** (sigma, high): This rule detects the creation of multiple known Diicot payloads at their specific, hardcoded file paths.
- **Linux_Diicot_SSH_Scanner** (sigma, medium): This rule detects the execution of the Diicot SSH scanner by its unique file path and specific command-line arguments.
- **Linux_Diicot_Scan_Result_Parsing** (sigma, medium): This rule detects a highly specific and complex shell command chain used by Diicot to process scan results, indicating active collection on a compromised host.
- **Net_Diicot_C2_DNS** (sigma, high): This rule detects DNS queries to the known Diicot C2 top-level domain, which is a strong indicator of compromise.
