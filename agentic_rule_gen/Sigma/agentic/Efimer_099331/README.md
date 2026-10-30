# Efimer

Source: https://www.reversinglabs.com/blog/threat-researchers-notebook-how-attackers-redirect-crypto-payments

Efimer is a Clipbanker malware that steals cryptocurrency by replacing wallet addresses in the clipboard. To evade detection, it specializes in matching the first or last one to three digits of the original address with an attacker-controlled one. The malware exfiltrates clipboard data and screenshots, uses Pyarmor for protection, and communicates with its C2 over TOR.

- **Efimer_C2_TOR_Domain_Query** (sigma, high): This rule detects C2 communications over TOR by matching highly specific, attacker-controlled .onion domains.
- **Efimer_Payload_Dropped** (sigma, high): This rule detects the creation of specific, uniquely named executables identified as Efimer malware payloads.
- **Efimer_Payload_Download** (sigma, high): This rule detects payload downloads by matching on specific URLs known to host Efimer malware.
- **Efimer_Payload_Download_Connection** (sigma, medium): This rule detects connections to a specific IP address and port identified as serving malware payloads.
