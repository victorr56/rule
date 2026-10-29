# GTFire

Source: https://www.group-ib.com/blog/gtfire-phishing-scheme/

GTFire is a large-scale phishing campaign abusing legitimate Google services to bypass security controls. It hosts phishing pages on Google Firebase (*.web.app) and uses Google Translate (translate.goog) as a redirector to disguise the malicious destination. Stolen credentials are exfiltrated via Base64-encoded GET request parameters to a PHP-based C2.

- **AllIn1PhishingKitExfil** (sigma, high): This rule detects a specific URI path associated with credential exfiltration by the "All-in-1" phishing kit.
- **GTFireC2** (sigma, high): This rule detects DNS queries for C2 domains specifically enumerated in the GTFire campaign intelligence.
