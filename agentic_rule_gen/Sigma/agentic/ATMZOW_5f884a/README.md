# ATMZOW

Source: https://www.group-ib.com/blog/switching-side-jobs/

ATMZOW is a JavaScript skimmer group, also known as 'Magento Guruincsite malware', active since at least 2015. The group has recently used Google Tag Manager (GTM) to inject its skimmer onto e-commerce sites, specifically targeting pages containing 'checkout' in the URL. The report links ATMZOW to a phishing campaign and the Hancitor malware group based on a shared JavaScript obfuscator and overlapping infrastructure.

- **ATMZOW_Group_C2_And_Phishing_Domains** (sigma, high): This rule keys on a list of high-confidence domains associated with ATMZOW C2, skimmer, and phishing infrastructure.
- **ATMZOW_Skimmer_Kit_URL_Request** (sigma, high): This rule precisely detects skimmer activity by correlating specific domains with the URI paths they use to host payloads or exfiltrate data.
