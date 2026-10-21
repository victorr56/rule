# The Ransomware Ground Game: How A Christmas Scanning Campaign Will Fuel 2026 Attacks

Source: https://www.greynoise.io/blog/christmas-scanning-campaign-fuel-2026-attacks

A single initial access broker operator used the ProjectDiscovery Nuclei scanner at industrial scale from two CTG Server Limited (AS152194) IPs over December 25-28, testing 240+ exploits and confirming hits via Interactsh out-of-band (OAST) callback domains. GreyNoise attributes 57,000+ unique OAST subdomains and a shared Machine ID/JA4 fingerprint across 98% of attempts to one operator, indicating harvested vulnerability inventory destined for ransomware affiliates. Detection should focus on DNS/sinkhole logs for oast.* callback lookups and network logs for the two scanning IPs.

- **Tool_Interactsh_OAST_Callback_DNS** (sigma, medium): This rule detects OAST callbacks to default Interactsh domains, a strong indicator of vulnerability exploitation.
- **Christmas_2026_Scanning_Campaign_IP** (sigma, medium): This rule detects scanning activity from two specific IP addresses used in the campaign.
