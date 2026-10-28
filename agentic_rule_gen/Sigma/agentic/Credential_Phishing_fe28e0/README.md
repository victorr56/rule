# Credential Phishing

Source: https://cofense.com/blog/locked-and-loaded-phishing-through-fake-bids-and-protected-documents

This credential phishing campaign uses an email with a password-protected PDF attachment themed around a project bid invitation. The PDF contains a link to a fake document sharing site, which then redirects the user to a fake Microsoft login page to harvest their credentials.

- **CredPhish_LastingOnlineExperiences_Domains** (sigma, high): This rule keys on a list of DNS domains that are highly specific to this credential phishing infrastructure.
- **CredPhish_Phishing_URL_Patterns** (sigma, high): This rule is precise because it combines specific domains/subdomains with unique URL path patterns from the campaign.
- **CredPhish_PDF_Attachment** (sigma, high): This rule detects a highly specific filename associated with the initial phishing attachment, making it a reliable indicator.
- **CredPhish_Redirector_IP** (sigma, medium): This rule keys on a specific IP address observed acting as a redirector, but carries a medium confidence due to its cloud hosting provider.
