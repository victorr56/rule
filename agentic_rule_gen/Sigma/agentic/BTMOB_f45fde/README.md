# BTMOB

Source: https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/

BTMOB is an Android remote access trojan evolved from SpySolr, sold as malware-as-a-service with an APK builder that lets operators cheaply generate phishing payloads and tailor lures per region. It spreads via fake app stores impersonating streaming, crypto-mining and government services, then abuses Android Accessibility Services to grant itself broad permissions, exfiltrate data, capture screenshots/recordings and take remote control of the device. Rapid payload turnover means indicators age quickly, though recurring infrastructure patterns remain useful for triage.

- **MAL_BTMOB_Builder_Oct2026** (yara, medium): This rule detects the BTMOB builder using a specific detection name and a combination of feature strings from the UI.
- **BTMOB_C2_DNS_Queries** (sigma, high): This rule detects DNS lookups for specific domains used by BTMOB for C2 and phishing.
- **BTMOB_C2_IP_Connections** (sigma, high): This rule detects network connections to a list of specific IP addresses used as C2 servers by BTMOB.
