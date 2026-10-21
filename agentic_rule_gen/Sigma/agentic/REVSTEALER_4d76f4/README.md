# REVSTEALER

Source: https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer

REVSTEALER (tracked as REF2859) is an emerging Windows infostealer distributed through hijacked YouTube channels advertising free game cheats and through samples masquerading as recognizable software. It harvests browser, wallet, VPN, messaging and gaming-platform credentials, applies CIS locale exclusion and a ten-check sandbox scoring system, and uses Polygon smart-contract dead drops to retrieve fallback C2 addresses. Four C2-delivered modules (ProManager, WinUpdate, SoftManager, LockAppHost) extend it with phishing overlays, clipboard cryptocurrency swapping, SOCKS5 backconnect and XMRig deployment.

- **MAL_REVSTEALER_Oct2026** (yara, high): The rule keys on unique REVSTEALER AES keys, C2 domains, and a specific Chrome ABE string, or a combination of supporting artifacts.
- **REVSTEALER_C2_And_Distribution_Domains** (sigma, high): This rule keys on a list of C2 and distribution domains that are specific to the REVSTEALER malware family.
- **Suspicious_Mscoree_DLL_Load_From_User_Desktop** (sigma, high): This rule detects `mscoree.dll` loading from a user's Desktop, a highly specific and suspicious path indicative of DLL hijacking.
- **REVSTEALER_Gaming_Credential_Access** (sigma, medium): This rule detects access to a specific list of gaming-related credential files by processes other than the legitimate game launchers.
- **Potential_Chrome_Credential_Looter_ElevationKatz** (sigma, medium): This rule keys on the specific combination of a Chromium browser process and debugging command-line flags used for credential theft.
