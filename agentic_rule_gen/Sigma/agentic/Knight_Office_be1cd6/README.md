# Knight Office

Source: https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack

Knight Office is a Microsoft 365 adversary-in-the-middle phishing kit whose Python Flask operator console is used to monitor captured sessions and replay stolen tokens, sidestepping passwords and MFA. Victims are drawn in via a self-spoofed DocuSign-style lure, a Monday.com open redirect and a compromised Joomla site, then handed a device authentication code for Microsoft's deviceauth flow. Stolen tokens are replayed from data-center and proxy infrastructure using the python-requests/2.34.2 user agent, followed by rogue Entra device registration and a Windows Hello for Business key credential.

- **MAL_KnightOffice_Phishkit_Console_Oct2026** (yara, high): This rule keys on highly specific branding and feature strings from the phishing kit's operator console interface.
- **MAL_KnightOffice_Phishkit_Landing_Oct2026** (yara, medium): This rule detects phishing pages by combining a confirmed device code prompt string with other kit-specific strings mentioned in reporting.
- **KnightOffice_Phishing_Domains** (sigma, high): This rule detects DNS queries for a list of domains known to be used exclusively by the Knight Office phishing kit.
- **KnightOffice_C2_IPs** (sigma, high): This rule detects network connections to IPs known to be part of the Knight Office C2 and phishing infrastructure.
