# Anthropic AI Phishing

Source: https://cofense.com/blog/would-your-employees-join-a-fake-anthropic-ai-preview

A credential phishing campaign uses a lure of an exclusive preview of Anthropic's AI technology to steal Google and Microsoft credentials. The attack leverages abused legitimate services like GoTo Webinar for email delivery and the zpr.io URL shortener, along with multiple CAPTCHA pages, to evade detection and lead victims to fake login portals.

- **Anthropic_AI_Phishing_Domains** (sigma, high): This rule detects DNS queries for highly specific, typosquatted domains used in the phishing campaign.
