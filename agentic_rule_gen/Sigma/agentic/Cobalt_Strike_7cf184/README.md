# Cobalt Strike

Source: https://www.group-ib.com/blog/opera1er-apt/

OPERA1ER is a French-speaking, financially motivated threat actor that has been targeting organizations in Africa since at least 2018. They utilize commodity malware such as Cobalt Strike and BitRAT. Their infrastructure can be identified through specific Cobalt Strike public key hashes and SSH fingerprints.

- **Opera1erC2Domains** (sigma, high): This rule detects OPERA1ER C2 domains from the provided threat intelligence.
- **Opera1erC2IpAddresses** (sigma, high): This rule detects network connections to OPERA1ER C2 IP addresses from the provided threat intelligence.
