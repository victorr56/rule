# Fake WatchGuard VPN credential phishing

Source: https://www.huntress.com/blog/fake-watchguard-vpn-credential-phishing

SEO-poisoning credential phish that pushes the lookalike domain watchguard-vpn[.]net as a WatchGuard Mobile VPN with SSL download site. A plain JavaScript modal (popup.js) posts the victim's VPN server, login and password as JSON to watchguard-ssl[.]online, deliberately rejecting the first submission to harvest a second set. After the second attempt the page downloads the genuine, validly signed WatchGuard installer from WatchGuard's own CDN, so no malicious file ever lands on the endpoint.

- **Storm2561_WatchGuard_Phishing_Domains_DNS** (sigma, high): This rule detects DNS lookups for specific typosquatted domains used for phishing and credential collection.
- **Storm2561_WatchGuard_Phishing_IPs** (sigma, high): This rule detects network connections to IP addresses hosting the phishing lure and credential collector.
