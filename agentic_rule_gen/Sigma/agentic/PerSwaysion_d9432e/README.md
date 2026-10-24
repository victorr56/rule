# PerSwaysion

Source: https://www.group-ib.com/blog/perswaysion/

PerSwaysion is a large-scale phishing campaign that abuses Microsoft file-sharing services like Sway, SharePoint, and OneNote to redirect victims to a credential harvesting page. The phishing kit uses modern JavaScript frameworks, features anti-analysis techniques, and is operated by multiple groups who conduct follow-on attacks by impersonating victims to their contacts.

- **MAL_PerSwaysion_Phishkit_Oct2026** (yara, medium): The rule keys on unique variable names, filenames, and other identifiers found in the PerSwaysion phishing kit's JavaScript components, ensuring high precision.
- **PerSwaysion_Phishing_Domains** (sigma, high): This rule detects DNS queries to specific phishing and data harvesting domains reported as PerSwaysion infrastructure.
