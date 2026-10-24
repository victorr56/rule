# G-Analytics

Source: https://www.group-ib.com/blog/g-analytics/

G-Analytics is a JavaScript web skimmer family, active since 2016, that steals payment card information from e-commerce websites, particularly those using Magento CMS. It evades detection by masquerading as legitimate services like Google Analytics and jQuery, and exfiltrates data to actor-controlled domains. Some variants can also inject malicious code into server-side PHP scripts.

- **GAnalyticsC2DNSQuery** (sigma, high): This rule detects DNS lookups for a list of specific C2 and typosquatted domains used by the G-Analytics skimmer.
