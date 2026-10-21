# Hidden in plain sight: How SVGs carry malicious scripts

Source: https://www.reversinglabs.com/blog/how-svgs-carry-dangerous-scripts

Malicious SVG files abuse the format's embedded JavaScript support to act as redirectors, self-contained phishing pages, or DOM/XSS script abuse, while appearing to be harmless images. Observed samples masquerade as fake voicemail attachments in spear-phishing campaigns and hide target emails (often base64-encoded) and redirect domains inside obfuscated markup. Because mail and web gateways treat SVG as an image, the format is an overlooked delivery and credential-harvesting vector.

- **Malicious_SVG_Redirector_Domain_Query** (sigma, high): This rule detects DNS queries for high-specificity domains used as redirectors by malicious SVG files.
- **Malicious_SVG_Exfiltration_To_Pinche_PHP** (sigma, medium): This rule detects HTTP requests to a specific PHP filename (`pinche.php`) used for exfiltration.
