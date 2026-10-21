# AuraStealer, ACRStealer (Amatera), Remus Stealer

Source: https://www.reversinglabs.com/blog/infostealers-highlight-malware-as-a-service-trend

ReversingLabs profiles three actively maintained infostealer malware-as-a-service families active between June and August 2026: AuraStealer (now virtualized and 10MB in size), ACRStealer/Amatera, and Remus Stealer, a 64-bit LummaStealer-like stealer that uniquely uses Etherhiding for C2. All three harvest browser credentials and crypto wallet data, rely on heavy anti-analysis and self-deletion, and are distributed through ClickFix, ClearFake, SEO poisoning and malvertising. The report provides hashes, download URLs and C2 domains for each family.

- **Sigma_AuraStealer_C2_Domain_DNS_Resolution** (sigma, high): Keys on the eight AuraStealer C2 domains published in the report; the .cfd TLD plus the single unrelated com domain are actor-owned and unrelated to legitimate egress.
- **Sigma_ACRStealer_Amatera_C2_Domain_DNS_Resolution** (sigma, high): Keys on the nine fully-qualified ACRStealer/Amatera C2 hostnames; the distinctive subdomain plus .cc combinations make benign collision implausible.
- **Sigma_Remus_Stealer_Etherhiding_C2_Connection** (sigma, high): Keys on the thirteen Remus Stealer C2 hostnames that the Etherhiding resolver yields; the random-looking .shop/.click/.biz/.surf/.garden/.courses labels are actor-specific.
- **Sigma_AuraStealer_Payload_Delivery_IP_Connection** (sigma, high): Keys on the five AuraStealer staging/delivery IPs combined with outbound connection initiation, which avoids matching inbound or unrelated listener traffic on those hosts.
