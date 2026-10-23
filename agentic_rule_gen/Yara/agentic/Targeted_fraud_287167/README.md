# Targeted fraud

Source: https://www.group-ib.com/blog/target/

Targeted fraud is a large-scale phishing campaign that uses personalized, cloaked links to redirect victims to fake survey and prize giveaway pages. The scheme, active in over 90 countries, aims to steal personal information and payment card details by generating unique URLs for each victim that contain a timestamp and hash to evade analysis. The infrastructure is vast, with attackers using many domain networks to ensure the campaign's persistence.

- **SUSP_HTML_Phishing_TargetedFraud_Oct2026** (yara, medium): This rule detects web-based phishing content from the 'Targeted Fraud' campaign by keying on a combination of specific phrases, domains, and URI paths mentioned in the report. All strings are sourced from prose and treated as supporting indicators, requiring three to match to increase precision and avoid false positives.
- **Targeted_Fraud_Phishing_Domain_Query** (sigma, high): This rule is based on high-specificity domain indicators directly linked to the phishing campaign's infrastructure.
