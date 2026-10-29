# Redirection Roulette

Source: https://www.wiz.io/blog/redirection-roulette

An unknown threat actor compromises tens of thousands of websites, primarily in East Asia, using stolen FTP credentials. They inject malicious JavaScript to conditionally redirect visitors to adult or gambling websites, a campaign the report calls 'Redirection Roulette'. The actor uses typo-squatted domains and geofencing to evade detection.

- **RedirectionRouletteMalwareScriptURI** (sigma, high): This rule detects a specific malicious script URI on a typosquatted domain, providing high-precision detection.
- **RedirectionRouletteFingerprintExfiltrationURI** (sigma, high): This rule targets a highly specific API path used for data exfiltration, making it a reliable indicator of compromise.
- **RedirectionRouletteC2AndRedirectionDomains** (sigma, high): This rule detects DNS queries for a list of domains specifically associated with the Redirection Roulette campaign.
- **RedirectionRouletteC2AndInfrastructureIPs** (sigma, high): This rule detects network connections to IP addresses identified as part of the Redirection Roulette infrastructure.
- **RedirectionRouletteDestinationDomainPattern** (sigma, medium): This rule detects a specific domain generation pattern ('alibb*.xyz') used for redirection, offering broader but still precise detection.
