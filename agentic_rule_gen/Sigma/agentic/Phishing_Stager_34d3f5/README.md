# Phishing Stager

Source: https://www.huntress.com/blog/terminal-server-phishing-stager-exposed

An actor used a compromised Windows terminal server to stage a large-scale phishing campaign targeting UK consumers. The actor used a legitimate bulk mailer, Gammadyne Mailer, to send millions of emails impersonating the Boots pharmacy chain from a compromised Bolivian government website. The campaign aimed to harvest personal and payment card data through a fake survey and checkout process.

- **GammadyneMailerExecutionFromPhishingStagingDirectory** (sigma, high): This rule keys on the mailer executable `gm.exe` running from a highly specific Romanian-named staging directory.
- **PhishingCampaignStagingDirectoryActivity** (sigma, high): This rule keys on the highly specific and unique Romanian directory name observed being used for staging.
- **GammadyneMailerPhishingProjectFileCreation** (sigma, high): This rule keys on a specific Gammadyne Mailer project filename, where 'dracii' means 'the devils' in Romanian.
- **DNSQueryForPhishingDomainIpelcGobBo** (sigma, high): This rule keys on a DNS query for a compromised Bolivian government domain used for phishing operations.
- **OutboundConnectionToBootsPhishingKitURL** (sigma, high): This rule keys on the combination of the phishing domain and the specific URI path for the phishing kit.
- **OutboundConnectionToPhishingOperatorIPAddresses** (sigma, medium): This rule keys on a list of IP addresses specifically attributed to the threat actor's infrastructure.
