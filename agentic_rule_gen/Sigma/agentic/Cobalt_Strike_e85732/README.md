# Cobalt Strike

Source: https://www.group-ib.com/blog/apt41-world-tour-2021/

In 2021, APT41 conducted campaigns using SQL injection for initial access to deploy custom Cobalt Strike beacons. The threat actor used a unique multi-stage payload delivery method involving chunked Base64 data written via `echo` and decoded with `certutil`. They also used a custom injector named StealthMutant to bypass ETW and AV.

- **APT_APT41_Tools_Oct2026** (yara, high): This rule keys on highly specific hardcoded passwords used by APT41, which are strong indicators.
- **APT41_Payload_Staging_With_Certutil** (sigma, high): This rule detects a highly specific command line used by APT41 to decode a staged payload using certutil, combining the process image with specific arguments and file names.
- **APT41_NTDS_dit_Credential_Dump** (sigma, high): This rule detects the specific command-line arguments used with ntdsutil.exe by APT41 to perform a credential dump, which is a high-fidelity indicator of compromise.
- **APT41_Suspicious_Service_Creation** (sigma, high): This rule detects the creation of Windows services with names specifically used by APT41, making it a precise indicator of this actor's persistence TTPs.
- **Suspicious_Mimikatz_like_Command_Line** (sigma, high): This rule combines a specific, non-standard executable name (`mi.exe`) with classic Mimikatz commands, creating a high-precision detection for credential dumping activity.
- **APT41_C2_Domain_Communication** (sigma, high): This rule detects DNS queries to a list of domains exclusively associated with APT41 C2 infrastructure, providing a high-confidence network indicator.
- **APT41_Payload_Staging_Via_Move** (sigma, high): This rule detects a specific command line used by APT41 to rename and move its payload, matching a generic process (`cmd.exe`) with highly specific, actor-related arguments.
