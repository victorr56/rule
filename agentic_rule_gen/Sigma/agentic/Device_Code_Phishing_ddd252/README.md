# Device Code Phishing

Source: https://www.huntress.com/blog/device-code-phishing-evolving-threats

Threat actors are conducting device code phishing campaigns to steal Microsoft 365 tokens by abusing infrastructure from VPS reseller BL Networks. This activity follows a similar playbook to an earlier campaign that abused the Railway PaaS, indicating an evolving threat that leverages legitimate-looking infrastructure for token replay attacks.

- **DeviceCodePhishingInfrastructureIP** (sigma, high): This rule keys on a list of IP addresses specifically identified as infrastructure for device code phishing campaigns.
