# SonicWall Credential Stuffer

Source: https://www.huntress.com/blog/sonicwall-credential-stuffing-campaign

A broad, opportunistic credential stuffing campaign targets SonicWall VPN and firewall accounts. The attacks, which appear to be automated credential validation, originate from a small set of IP addresses hosted on DigitalOcean.

- **SonicWallCredentialStuffingCampaignIPs** (sigma, high): This rule detects connections to a list of IPs identified in a SonicWall credential stuffing campaign, as per the reference.
