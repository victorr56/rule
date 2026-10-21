# GoldFactory

Source: https://www.group-ib.com/blog/goldfactory-ios-trojan/

GoldFactory is a Chinese-speaking threat actor targeting iOS and Android users in the APAC region, particularly Vietnam and Thailand. Their malware suite, which includes GoldDigger and GoldPickaxe, steals facial recognition data to create AI deepfakes for bypassing banking app biometrics. The malware also exfiltrates PII and SMS messages, and is distributed via smishing, leading to TestFlight or MDM profile installations for iOS, and fake app stores for Android.

- **APT_GoldFactory_GoldDigger_Oct2026** (yara, medium): This rule keys on unique API endpoints and a specific Activity name associated with GoldDigger malware.
- **GoldFactory_Malware_C2_URI_Paths** (sigma, high): This rule detects multiple specific C2 URI paths unique to the GoldFactory malware family, making it a high-precision indicator of compromise.
