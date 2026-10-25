# 0ktapus

Source: https://www.wiz.io/blog/unmasking-phishing-strategies-for-identifying-0ktapus-domains

0ktapus (Scattered Spider) is a financially motivated threat actor known for using sophisticated social engineering and phishing to gain initial access. Their campaigns leverage numerous phishing kits and web page templates with distinct characteristics, which are used to mimic legitimate login pages and harvest credentials. The actor frequently reuses infrastructure and targets organizations in the IT, finance, and insurance sectors.

- **ScatteredSpider_Phishing_Kit_Exfil_Template_H** (sigma, high): This rule detects a highly specific URI path used for POSTing data in a known phishing template.
- **ScatteredSpider_Phishing_Domain_DNS_Query** (sigma, high): This rule detects DNS queries for a list of domains explicitly linked to Scattered Spider phishing campaigns.
- **ScatteredSpider_Phishing_Kit_Asset_Template_K** (sigma, high): This rule detects requests for uniquely named asset files from a specific 0ktapus phishing template.
- **ScatteredSpider_Phishing_Kit_Asset_Nike** (sigma, high): This rule detects a request for a uniquely named asset file observed in a Scattered Spider phishing kit.
- **ScatteredSpider_Phishing_Kit_Asset_DoorDash** (sigma, high): This rule detects a request for a uniquely named image file observed in a Scattered Spider phishing kit.
