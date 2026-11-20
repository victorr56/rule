# Microsoft 365 Outage Phishing

Source: https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/

A high-volume credential phishing campaign uses lures impersonating Microsoft 365 service health notifications. The emails use sender domains like moments-notice.com and subjects such as 'Outage - <random>' to create urgency, luring users to click links leading to credential harvesting sites.

- **M365_Outage_Phish_DNS** (sigma, high): This rule detects DNS queries for high-specificity credential harvesting domains.
- **M365_Outage_Phish_Network** (sigma, medium): This rule detects network connections to a specific IP and port used for tracking.
