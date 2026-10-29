# Meta Business Phishing

Source: https://www.huntress.com/blog/meta-business-manager-phishing

An unknown threat actor abused Meta's business partner service to send validated phishing emails containing non-clickable URLs in the business name field. These lures led to phishing pages, some incorporating a chatbot, designed to steal Meta credentials, MFA codes, and ID documents. Stolen data was exfiltrated to a private Telegram channel, with some exfiltration messages containing Vietnamese-language strings.

- **MetaBusinessPhishing_Proxy_URL** (sigma, high): This rule detects proxy traffic to specific URLs and paths used in the Meta Business phishing campaign.
- **MetaBusinessPhishing_Network** (sigma, high): This rule detects network connections to domains specifically created for this phishing campaign.
