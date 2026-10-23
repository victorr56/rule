# TinyFluff

Source: https://www.group-ib.com/blog/oldgremlin-comeback/

OldGremlin is a Russian-speaking ransomware gang that resumed attacks against Russian companies in March 2022. Their recent campaigns leverage TinyFluff, a custom Node.js-based backdoor delivered via malicious documents, which uses DNS tunneling for C2 communications and system reconnaissance.

- **APT_OldGremlin_TinyFluff_Oct2026** (yara, medium): The rule keys on a unique Base64-encoded public key and a hardcoded RC4 key, both confirmed to be in the binary. The public key is long and distinctive enough to fire the rule alone. The RC4 key is combined with supporting strings mentioned in the report to ensure precision.
- **OldGremlin_TinyFluff_WebDAV_Execution** (sigma, high): This rule detects a highly specific command line used to mount a WebDAV share from a known malicious IP and execute a payload.
- **OldGremlin_TinyFluff_C2_IP_Connections** (sigma, high): This rule detects network connections to IP addresses known to be used by OldGremlin for C2 and payload delivery.
- **OldGremlin_TinyFluff_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains known to be associated with the OldGremlin C2 infrastructure.
