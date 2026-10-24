# E1RB

Source: https://www.group-ib.com/blog/e1rb/

E1RB is a JavaScript sniffer family based on Grelos that steals payment card information from e-commerce websites. It employs server-side polymorphism to generate unique script samples for each visitor, including randomizing function/variable names and using time-based obfuscation. The sniffer is loaded when checkout-related keywords are found in the URL and injects a fake payment form to capture and exfiltrate data.

- **E1RB_Skimmer_C2_Domain** (sigma, high): This rule detects DNS queries for domains specifically registered for and used by the E1RB skimmer malware.
- **E1RB_Skimmer_Script_And_Exfil_URL** (sigma, high): This rule matches full, unique URLs used by the E1RB skimmer to load its payload and exfiltrate stolen data.
- **E1RB_Skimmer_URI_Path** (sigma, medium): This rule detects specific URI paths used by E1RB, which is more resilient to domain changes than IOC-based rules.
