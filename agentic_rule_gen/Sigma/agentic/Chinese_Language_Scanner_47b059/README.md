# Chinese Language Scanner

Source: https://isc.sans.edu/diary/rss/33442

An automated scanning campaign, primarily from AS-7456 (Canada), probes internet-facing endpoints. The activity is distinguished by the use of specific HTTP headers that indicate a strong preference for Chinese language character sets (GBK, zh-CN).

- **ChineseLanguageScannerGBKHeader** (sigma, high): This rule detects a highly specific Accept-Charset HTTP header string used by the scanner, which is a durable behavioral indicator.
- **ChineseLanguageScannerIPs** (sigma, high): This rule detects network connections to a list of specific IP addresses observed as part of the scanning infrastructure.
- **ChineseLanguageScannerDomains** (sigma, high): This rule detects DNS lookups for specific domains observed as part of the scanning infrastructure.
