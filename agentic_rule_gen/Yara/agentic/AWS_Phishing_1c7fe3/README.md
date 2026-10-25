# AWS Phishing

Source: https://www.wiz.io/blog/emerging-phishing-campaign-targeting-aws-accounts

An unknown threat actor is conducting a phishing campaign targeting AWS users. The attack starts with an email containing a link to a credential harvesting page designed to look like the AWS login page. The campaign uses lookalike domains, link shorteners, and infrastructure hosted on services like Namecheap and Hostinger to achieve its objectives.

- **MAL_Phish_AWS_Page_Oct2026** (yara, low): The rule keys on a combination of specific URLs and domains used in an AWS phishing campaign, making it precise against the phishing kit's content.
- **AWS_Phishing_Campaign_Domain_Queries_Oct26** (sigma, high): This rule detects DNS queries for a list of specific, attacker-controlled domains used in a phishing campaign.
- **AWS_Phishing_Campaign_C2_Connection_Oct26** (sigma, medium): This rule detects network connections to historic IPs used by the phishing infrastructure; level is medium due to potential IP reuse.
