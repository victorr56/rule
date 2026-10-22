# Godfather

Source: https://www.group-ib.com/blog/godfather-trojan/

Godfather is an Android banking trojan, forked from the Anubis malware family, distributed via decoy apps on Google Play. It abuses AccessibilityService to steal credentials via web fakes, capture screen recordings, and exfiltrate data from over 400 financial applications. It retrieves its C2 address from Telegram channel descriptions and uses a custom protocol for communication.

- **Godfather_Android_Authenticator_Masquerade** (sigma, high): This rule detects the specific fake package name used by Godfather to masquerade as Google Authenticator, a high-fidelity indicator for Android environments.
- **Godfather_C2_Domain_DNS_Query** (sigma, high): This rule keys on a list of C2 domains explicitly associated with Godfather.
- **Godfather_C2_Communication_URI_Path** (sigma, high): This rule detects specific and unique C2 URI paths used by Godfather for various operations.
- **Godfather_C2_IP_Address_Connection** (sigma, high): This rule detects network connections to a known Godfather C2 IP address.
- **Godfather_Hardcoded_User_Agent** (sigma, medium): This rule detects a specific, hardcoded User-Agent string associated with Godfather communications.
