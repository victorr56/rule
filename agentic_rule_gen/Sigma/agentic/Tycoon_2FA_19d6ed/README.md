# Tycoon 2FA

Source: https://www.elastic.co/security-labs/threat-command/tycoon-2fa-aitm-detection-engineering

Tycoon 2FA is a Phishing-as-a-Service AiTM kit (attributed to Storm-1747) that reverse-proxies Entra ID and Google Workspace login flows to steal post-MFA session tokens, using cheap cloud-VPS relay IPs with Node.js HTTP clients and a residential-proxy operator console. Detection anchors include Node.js user agents (node, axios, undici) on Auth Broker/OfficeHome sign-ins, device-registration abuse for primaryRefreshToken persistence, and rapid multi-category Microsoft Graph reconnaissance from the same user within minutes of token issuance.

- **Tycoon2FA_AiTM_Rogue_Device_Registration_With_Axios** (sigma, high): This rule detects a suspicious 'axios' user-agent in Entra ID device registration events, a specific behavior of the Tycoon 2FA kit.
- **Tycoon2FA_AiTM_DRS_Abuse_For_Persistence** (sigma, high): This rule detects a specific combination of hostname, URL path, and HTTP method used for DRS abuse, a key persistence tactic for this actor.
- **Tycoon2FA_Phishing_Domain_DNS_Query** (sigma, high): This rule detects DNS queries for known high-confidence Tycoon 2FA phishing domains from the threat profile.
- **Tycoon2FA_Kit_IP_Reputation_Check** (sigma, medium): This rule detects a DNS query for an IP reputation service, a TTP used by the Tycoon 2FA kit for anti-analysis.
