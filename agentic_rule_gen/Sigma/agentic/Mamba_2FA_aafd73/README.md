# Mamba 2FA

Source: https://www.darktrace.com/blog/a-snake-in-the-net-defending-against-aitm-phishing-threats-and-mamba-2fa

Mamba 2FA is a Phishing-as-a-Service (PhaaS) kit with Adversary-in-the-Middle (AiTM) capabilities targeting services like Microsoft 365. It uses convincing phishing pages with a distinct URL structure and HTML attachments to steal credentials and bypass MFA by capturing session data in real-time. Post-compromise actions include creating email rules and registering new authenticators for persistence.

- **Mamba_2FA_Associated_IPs** (sigma, high): This rule detects connections to IPs specifically identified as Mamba 2FA relay servers or used for post-compromise logins.
