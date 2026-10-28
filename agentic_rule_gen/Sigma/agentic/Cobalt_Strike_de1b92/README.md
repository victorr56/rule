# Cobalt Strike

Source: https://www.elastic.co/security-labs/blog/extracting-cobalt-strike-beacon-configurations

This report details the manual extraction and analysis of a Cobalt Strike beacon configuration from a memory-dumped payload. Key configuration fields such as sleeptime, jitter, C2 server, public key, license ID (watermark), and process injection settings can be used for detection, infrastructure tracking, and clustering threat activity. The process-inject.stub field contains an MD5 hash of the Cobalt Strike JAR file, allowing for version identification.

- **HKTL_Cobalt_Strike_Beacon_Config_Strings_Oct2026** (yara, medium): This rule keys on unique Base64-encoded values and other configuration parameters found in Cobalt Strike beacon payloads.
- **CobaltStrike_C2_Domain_clevelandclinic_cloud** (sigma, high): This rule detects DNS queries for a known Cobalt Strike C2 domain.
- **CobaltStrike_C2_IPs_Oct26** (sigma, high): This rule detects network connections to known Cobalt Strike C2 IP addresses.
