# Inferno Drainer

Source: https://www.group-ib.com/blog/declaration-trap/

A phishing campaign impersonates European tax authorities, such as the Dutch Belastingdienst, using urgent emails to lure victims to fake government portals. These sites aim to steal cryptocurrency by either tricking users into submitting their wallet's seed phrase or by having them approve malicious transactions via WalletConnect, leveraging the Inferno Drainer kit.

- **InfernoDrainerPhishingDomains** (sigma, high): This rule detects DNS queries for a list of domains specifically created for the Inferno Drainer phishing campaign.
- **InfernoDrainerAdminPanelAccess** (sigma, high): This rule detects access to a specific URL path, '/include_admin', identified as the admin panel for the Inferno Drainer phishing kit.
- **InfernoDrainerMaliciousScriptAccess** (sigma, medium): This rule detects requests for 'wallet-connect-v4.js', a file name specifically mentioned as part of the Inferno Drainer toolkit.
