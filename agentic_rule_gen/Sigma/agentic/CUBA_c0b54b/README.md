# CUBA

Source: https://www.elastic.co/security-labs/threat-command/cuba-ransomware-malware-analysis

CUBA is a Windows ransomware that encrypts local and network shares, controlled via command-line arguments. It terminates specific processes and services before encrypting files with ChaCha20/RSA and adding a '.cuba' extension, leaving behind a ransom note.

- **MAL_CUBA_Ransomware_Oct2026** (yara, high): The rule uses long, unique ransom note strings as strong indicators, and a combination of supporting strings including the .onion URL, file extension, and a reported file marker.
- **CubaRansomwareNote** (sigma, high): This rule detects the creation of the highly specific CUBA ransomware note filename.
- **CubaRansomwareTorLeakSite** (sigma, high): This rule detects network traffic to a unique .onion domain associated with CUBA ransomware's leak site.
