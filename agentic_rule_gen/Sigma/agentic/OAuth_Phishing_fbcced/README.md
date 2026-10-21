# OAuth Phishing

Source: https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection

UTA0352 conducts OAuth phishing campaigns against Microsoft Entra ID to acquire authorization codes. These codes are used to either access Microsoft Graph API by impersonating the VSCode client for data exfiltration, or to register a malicious device using ROADtools to mint a Primary Refresh Token (PRT) for persistent, privileged access.

- **APT_UTA0352_OAuth_Phishing_Oct2026** (yara, medium): This rule keys on unique client IDs and redirect URLs observed in UTA0352's OAuth phishing infrastructure. These are strong indicators unlikely to be found in legitimate software.
- **UTA0352_VSCode_OAuth_Phishing_URL** (sigma, high): This rule detects the specific combination of OAuth parameters used in the VSCode-impersonating phishing URL.
- **UTA0352_Device_Registration_Phishing_URL** (sigma, high): This rule detects the specific combination of OAuth parameters used for malicious device registration.
- **Suspicious_ROADtools_Auth_File_Creation** (sigma, medium): This rule detects the creation of a specific credential file used by the ROADtools framework.
