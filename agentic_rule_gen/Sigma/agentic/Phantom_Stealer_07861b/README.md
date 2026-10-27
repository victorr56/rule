# Phantom Stealer

Source: https://www.group-ib.com/blog/phantom-stealer-credential-theft/

Phantom Stealer is a commercial .NET-based infostealer sold as part of the 'Phantom Project' toolkit. Delivered via phishing, it harvests credentials, session data, and cryptocurrency information, exfiltrating it via Telegram, Discord, SMTP, or FTP.

- **PhantomStealerC2IPs** (sigma, high): This rule keys on a list of IP addresses specifically associated with Phantom Stealer C2 infrastructure.
- **PhantomStealerC2Domains** (sigma, high): This rule keys on a list of domain names specifically associated with Phantom Stealer C2 infrastructure.
