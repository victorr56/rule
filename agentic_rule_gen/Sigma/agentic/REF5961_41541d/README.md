# REF5961

Source: https://www.elastic.co/security-labs/threat-command/introducing-the-ref5961-intrusion-set

REF5961 is a China-nexus intrusion set primarily targeting government entities in Southern and Southeastern Asia. The actors deploy three new malware families—EAGERBEE, RUDEBIRD, and DOWNTOWN—for initial access, persistence, reconnaissance, and execution of additional payloads. The tooling often exhibits unsophisticated development practices, such as leaving debug strings and using suboptimal coding techniques, which provide unique detection opportunities.

- **MAL_REF5961_EAGERBEE_Oct2026** (yara, medium): The rule keys on strong unique strings and a code pattern from EAGERBEE, including a schedule string, C2 domain, and decryption logic. An alternative clause detects a combination of weaker but still characteristic strings.
- **MAL_REF5961_DOWNTOWN_Oct2026** (yara, high): The rule uses multiple highly specific, long, and unique strings from the DOWNTOWN malware, including a misspelled export name ("GetPluginInfomation") and distinctive debug strings. Any one of these is sufficient for a high-confidence detection.
- **MAL_REF5961_RUDEBIRD_Oct2026** (yara, medium): This rule is anchored on a specific 28-byte hexadecimal pattern provided by the researchers, which constitutes a strong and reliable indicator for the RUDEBIRD malware. Supporting strings are included for context but not required for a match.
- **REF5961_RUDEBIRD_PsExec_Lateral_Movement** (sigma, high): This rule detects a highly specific command line used by REF5961 for lateral movement, combining a renamed PsExec in an unusual path with specific arguments and payload name.
- **REF5961_EAGERBEE_Exfiltration_URL** (sigma, high): This rule detects exfiltration to specific compromised government websites, keying on the unique combination of legitimate-looking domains and a specific upload script path.
- **REF5961_C2_Domain_Query** (sigma, high): This rule detects DNS queries for domains exclusively associated with REF5961 C2 infrastructure.
- **REF5961_C2_IP_Connection** (sigma, high): This rule detects network connections to IP addresses exclusively associated with REF5961 C2 infrastructure.
