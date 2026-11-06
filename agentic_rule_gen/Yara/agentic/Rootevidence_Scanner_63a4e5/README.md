# Rootevidence Scanner

Source: https://isc.sans.edu/diary/rss/33492

A vulnerability scanner operated by Rootevidence targets a Cisco IOS vulnerability (suspected CVE-2023-20198). The scanner is identifiable by its unique User-Agent 'RootEvidence/1.0', custom 'Opt-Out-*' HTTP headers, and a URL-encoded request path '/%77ebui_wsma_https'.

- **APT_Rootevidence_Scanner_Nov2026** (yara, high): This rule detects the Rootevidence scanner using two unique strings from its network traffic: its custom User-Agent and a specific URL-encoded path.
- **RootevidenceScannerActivity** (sigma, high): This rule detects the unique User-Agent and URL path used by the Rootevidence scanner.
