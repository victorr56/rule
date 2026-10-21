# RUSTBUCKET

Source: https://www.elastic.co/security-labs/threat-command/DPRK-strikes-using-a-new-variant-of-rustbucket

A new variant of the RUSTBUCKET malware, attributed to BlueNorOff (Lazarus Group), targets macOS systems in financially motivated attacks. This version adds a persistence mechanism using a LaunchAgent plist to execute the malware on user login. The malware uses custom User-Agent strings to download subsequent stages and communicates with a dynamic C2 infrastructure.

- **APT_BlueNorOff_RUSTBUCKET_macOS_Oct26** (yara, high): The rule keys on a highly unique hardcoded User-Agent string and a combination of supporting strings from the binary and report prose.
- **BlueNorOff_RUSTBUCKET_Persistence_LaunchAgent** (sigma, high): This rule keys on the specific, masqueraded LaunchAgent plist filename used by RUSTBUCKET for persistence.
- **BlueNorOff_RUSTBUCKET_Persistent_Payload_Execution** (sigma, high): This rule keys on the specific malware execution path and the presence of a URL argument, characteristic of its C2 communication.
- **BlueNorOff_RUSTBUCKET_C2_Domain_Query** (sigma, high): This rule keys on a list of C2 domains specifically associated with RUSTBUCKET malware infrastructure.
