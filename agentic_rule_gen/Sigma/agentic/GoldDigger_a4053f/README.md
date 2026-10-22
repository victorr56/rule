# GoldDigger

Source: https://www.group-ib.com/blog/golddigger-fraud-matrix/

GoldDigger is an Android Trojan, active since June 2023, targeting financial applications in Vietnam. It abuses Android's Accessibility Service to steal credentials and SMS messages, and is protected by Virbox Protector to hinder analysis. The malware is distributed via fake websites masquerading as government portals and corporate sites.

- **golddigger_domains_proxy** (sigma, high): This rule detects HTTP/S requests to a list of specific C2 and delivery domains for the GoldDigger malware.
