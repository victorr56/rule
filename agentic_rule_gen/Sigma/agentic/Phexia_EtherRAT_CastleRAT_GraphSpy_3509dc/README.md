# Phexia, EtherRAT, CastleRAT, GraphSpy

Source: https://redcanary.com/blog/threat-intelligence/intelligence-insights-august-2026/

This Zscaler/Red Canary Intelligence Insights roundup covers July 2026's top 10 threats, with debuts by GraphSpy, Phexia, CastleRAT and EtherRAT. Three of the new entrants (Phexia, CastleRAT, EtherRAT) use blockchain-based dead drop resolution ("EtherHiding") to dynamically fetch C2 URLs from public RPC endpoints and smart contracts. Phexia resolves a C2 URL from a Polygon smart contract and pipes the response into osascript, while EtherRAT is delivered via a paste-and-run MSI and runs disguised as .ini/.tmp/.dat files.

- **MAL_Phexia_EtherHiding_Oct2026** (yara, medium): This rule keys on Phexia's unique Polygon contract address and its EtherHiding C2 technique indicators.
- **Phexia_EtherHiding_C2_Beacon** (sigma, high): This rule detects the novel 'EtherHiding' C2 resolution technique by matching `curl` execution with the specific smart contract address and function selector used by Phexia.
- **EtherRAT_MSI_Download_Command** (sigma, high): This rule is precise by combining the parent-child process relationship (`cmd.exe` > `curl.exe`) with specific command-line arguments, including the malware's C2 domain.
- **Phexia_macOS_Downloader_Curl_Command** (sigma, high): This rule is precise by detecting `curl` execution with the specific malicious domain and URI path used by Phexia for its initial payload download.
- **Phexia_EtherRAT_C2_DNS_Query** (sigma, high): This rule provides high-confidence network detection by keying on DNS queries for domains explicitly identified as malicious infrastructure for Phexia and EtherRAT.
