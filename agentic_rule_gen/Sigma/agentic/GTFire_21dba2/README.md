# GTFire

Source: https://www.group-ib.com/blog/gtfire-phishing-scheme-es/

GTFire is a large-scale phishing campaign that abuses Google Firebase (web.app) for hosting and Google Translate (translate.goog) as a redirector to evade detection. The scheme uses multi-step credential harvesting via commercial PHP phishing kits and exfiltrates data, including Base64-encoded passwords, through HTTP GET requests.

- **Allin1_Phishing_Kit_Exfiltration** (sigma, high): This rule detects the specific credential exfiltration path `/myown/All-in-1.php` associated with the "All-in-1" phishing kit.
- **GTFire_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains listed as C2 infrastructure for the GTFire campaign.
- **Suspicious_Google_Translate_Redirector_Usage** (sigma, medium): This rule detects the use of Google Translate as a redirector by keying on the `translate.goog` domain and specific URL parameters used in this technique.
