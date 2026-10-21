# ChatGPT-themed credential phishing

Source: https://cofense.com/blog/chatbot-conundrum-phishing-attempts-of-openai-s-chatgpt

Credential-phishing campaign that spoofs OpenAI/ChatGPT subscription renewal notices to steal ChatGPT account credentials and payment data. Victims receive an invoice-themed email from a lookalike nxcli.io sender domain whose button points to a Google API redirect that forwards to the actor's phishing login page hosted on the same infrastructure.

- **suspected_chatgpt_phishing_domain_query** (sigma, high): This rule detects DNS queries for specific subdomains identified as part of a ChatGPT-themed phishing campaign.
- **suspected_chatgpt_phishing_kit_access** (sigma, high): This rule combines the specific phishing kit path `/fertaq/app/` and the observed hosting provider TLD `nxcli.io` for a high-precision detection.
