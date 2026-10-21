# Active Reconnaissance Campaign Targets SonicWall Firewalls Through Commercial Proxy Infrastructure

Source: https://www.greynoise.io/blog/active-reconnaissance-campaign-targets-sonicwall-firewalls-through-commercial-proxy-infrastructure

A four-day reconnaissance campaign (Feb 22-25, 2026) generated 84,142 sessions from 4,305 IPs against exposed SonicWall SonicOS firewalls, with 92% of traffic probing the SSL VPN status-check API to build a target list for later credential attacks. Activity was delivered by four infrastructure clusters, including a commercial proxy service (ByteZero) that supplied 27,119 sessions from 4,102 rotating exit IPs and a single mega-scanner cycling 26 user agents. Detection should focus on management/VPN endpoint URIs, the HTTP/1.0-with-modern-Chrome-UA mismatch, and the listed scanning infrastructure ranges.

- **SUSP_Recon_SonicWall_Probing_Feb26** (yara, medium): The rule keys on specific SonicWall URI paths from a reconnaissance campaign. The unique API path can fire alone, while login paths require supporting indicators for precision.
- **SonicWall_SSLVPN_Status_Check_API_Reconnaissance** (sigma, high): This rule detects probes against a specific, high-volume API endpoint used for reconnaissance against SonicWall firewalls.
- **SonicWall_Login_Interface_Reconnaissance** (sigma, high): This rule detects probes against specific SonicWall login URIs associated with the reconnaissance campaign.
- **Anomalous_HTTP1_With_Modern_Chrome_UA** (sigma, medium): This rule detects a behavioral mismatch between User-Agent and HTTP version, a specific TTP of the scanning campaign.
- **Network_Connection_To_SonicWall_Recon_Scanner_IP** (sigma, high): This rule detects connections to a list of specific IP addresses identified as dedicated scanners in the campaign.
- **DNS_Query_For_ByteZero_Proxy_Domain** (sigma, medium): This rule detects DNS lookups for a commercial proxy provider heavily used by the attackers for their scanning infrastructure.
