# SNCF Phishing Scam

Source: https://www.group-ib.com/blog/french-railway-two-step-scam/

A multi-stage scam targets French railway (SNCF) customers with phishing emails promoting fake discounts. After an initial payment, attackers pose as bank counselors via phone to social engineer victims into authorizing further fraudulent transactions.

- **MAL_SNCF_Phishing_Web_Oct2026** (yara, high): This rule detects phishing pages and emails by keying on unique, explicit domains used in the campaign.
- **SNCFPhishingScam_Domain_Query** (sigma, high): This rule detects DNS lookups for a list of domains explicitly identified as part of the SNCF phishing campaign.
- **SNCFPhishingScam_IP_Connection** (sigma, high): This rule detects network connections to IP addresses explicitly identified as phishing infrastructure for the SNCF campaign.
