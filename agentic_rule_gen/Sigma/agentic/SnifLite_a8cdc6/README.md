# SnifLite

Source: https://www.group-ib.com/blog/ultrarank/

UltraRank uses a JS-sniffer from the SnifLite family to steal payment card data from e-commerce checkout pages. The malware is hosted on, and exfiltrates data to, domains mimicking Google Tag Manager, such as googletagsmanager.co. The sniffer activates on pages with URLs containing keywords like 'checkout' or 'cart' and stores stolen data in a local storage object named 'google.verify.cache.001'.

- **ultrarank_sniflite_c2_domains** (sigma, high): This rule detects DNS queries for domains used by UltraRank's SnifLite card skimmer, which are highly specific typosquats of legitimate services.
- **ultrarank_sniflite_c2_ips** (sigma, medium): This rule detects network connections to IP addresses reported as part of the UltraRank SnifLite C2 infrastructure.
