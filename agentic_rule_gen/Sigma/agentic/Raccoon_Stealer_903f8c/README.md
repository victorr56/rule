# Raccoon Stealer

Source: https://www.group-ib.com/blog/fakesecurity-raccoon/

FakeSecurity distributes Raccoon Stealer using phishing pages (Mephistophilus kit) and malicious documents, continuing a campaign that previously used the Vidar stealer. Raccoon exfiltrates credentials and crypto wallet data, using a public Telegram channel to retrieve its C2 server address. In some cases, Raccoon was also used to download the AveMaria RAT as a secondary payload.

- **HKTL_Raccoon_Stealer_Gen_Oct2026** (yara, medium): This rule keys on a unique slogan and a descriptive string found in the Raccoon Stealer tool.
- **APT_FakeSecurity_Raccoon_Variant_Oct2026** (yara, low): This rule detects actor-specific Raccoon Stealer samples using a confirmed Telegram channel name combined with unverified C2 domains from the same campaign.
- **Raccoon_Stealer_C2_Beacon_via_Telegram** (sigma, high): This rule detects a highly specific URL used by Raccoon Stealer to retrieve its C2 configuration.
- **Raccoon_Stealer_Execution_from_Office_Application** (sigma, high): This rule combines a specific process name with a suspicious parent process (MS Office), a common TTP for macro-based malware delivery.
- **FakeSecurity_Campaign_Payload_Domains** (sigma, high): This rule detects DNS lookups for a list of domains exclusively used for malware distribution and C2 in this campaign.
- **FakeSecurity_Campaign_C2_Server_Connection** (sigma, high): This rule detects network connections to IP addresses identified as C2 infrastructure for this campaign.
- **FakeSecurity_Campaign_Payload_Download_Paths** (sigma, high): This rule detects downloads of malware payloads by matching specific, unique URI paths observed in the campaign.
