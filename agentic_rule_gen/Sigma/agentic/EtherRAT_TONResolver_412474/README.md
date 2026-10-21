# EtherRAT, TONResolver

Source: https://cofense.com/blog/from-guest-complaints-to-malware-blockchain-abuse-targets-hotels

EtherRAT and TONResolver are NodeJS-based malware families delivered via malicious LNK shortcuts masquerading as JPG images in email campaigns targeting the hotel/accommodation industry. Instead of hardcoded C2, both resolve their current C2 address at runtime by reading data stored in Ethereum (EtherRAT) or TON (TONResolver) blockchain smart contracts via public APIs, enabling cheap C2 rotation and resisting takedown. Detection should focus on blockchain JSON-RPC/API lookups (eth_call), NodeJS runtime execution spawned by image-like LNK files, and the blockchain-derived C2 domains listed here.

- **MAL_EtherRAT_TONResolver_Oct2026** (yara, high): This rule keys on the unique Ethereum and TON smart contract addresses used by EtherRAT and TONResolver for C2 resolution.
- **EtherRAT_TONResolver_Blockchain_C2_Lookup** (sigma, high): This rule detects the malware's unique blockchain-based C2 resolution mechanism by keying on the specific smart contract addresses in HTTP request bodies.
- **EtherRAT_TONResolver_C2_DNS_Query** (sigma, high): This rule detects DNS lookups for a list of known C2 domains associated with EtherRAT and TONResolver.
- **EtherRAT_TONResolver_Lure_URL_Access** (sigma, high): This rule detects web requests to specific, high-confidence URLs used in the initial delivery phase of the malware.
