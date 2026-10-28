# ShinyHunters

Source: https://krebsonsecurity.com/2026/10/feds-suspect-ransom-negotiator-ran-shinyhunters-extortion-site/

ShinyHunters is a data extortion group that steals sensitive information and uses a dedicated leak site, shinywire.com, to pressure victims into paying a ransom. The group has demonstrated close relationships with ransomware negotiators, with some associates allegedly helping to operate the extortion infrastructure. Operators communicate via Telegram, complaining about incident response firms that advise victims against payment.

- **DnsQuery_ShinyHunters_ExtortionSite_Oct26** (sigma, high): This rule detects DNS queries to the specific extortion site domain `shinywire.com`, a high-fidelity indicator for the ShinyHunters group.
