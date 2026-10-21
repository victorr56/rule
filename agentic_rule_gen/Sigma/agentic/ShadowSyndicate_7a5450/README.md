# ShadowSyndicate

Source: https://www.group-ib.com/blog/new-shadowsyndicate-infrastructure/

ShadowSyndicate is a malicious infrastructure cluster, likely an IAB or bulletproof hosting service, linked to multiple ransomware campaigns. The actor uses shared SSH fingerprints to manage C2 servers for tools like Cobalt Strike, Havoc, and Sliver, and has been observed rotating keys and reusing servers across clusters.

- **ShadowSyndicate_C2_IPs** (sigma, high): This rule detects connections to a list of known C2 IPs from the threat profile.
- **ShadowSyndicate_C2_Domain_Query** (sigma, high): This rule detects DNS queries for the specific C2 domain `fortiveme.net`.
