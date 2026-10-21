# WWAHost WinRT Abuse (AppX sideloading OAuth token theft)

Source: https://www.huntress.com/blog/stealing-oauth-tokens-through-microsofts-front-door

A post-compromise technique sideloads a minimal AppX package whose ContentUriRules grants WindowsRuntimeAccess="all", so Microsoft-signed WWAHost.exe renders attacker JavaScript with full WinRT access and abuses WebAuthenticationBroker with Microsoft Office's first-party client ID to capture real OAuth authorization codes, access tokens and refresh tokens. Every component is Microsoft-signed and the login is genuine, so detection keys on the EdgeHTML user agent MSAppHost/3.0 (Edge/18) reaching non-Microsoft destinations from an AppX web host. Stolen refresh tokens give MFA-surviving Microsoft 365 access that scales with the victim's privileges.

- **MAL_WWAHost_WinRT_Abuse_SetupScript_Oct2026** (yara, medium): This rule targets attacker setup scripts by detecting a unique banner string or a combination of strings related to AppX registration, sideloading policy settings, and specific package names from the research.
- **WWAHost_WinRT_Abuse_OAuth_Token_Theft_via_Suspicious_User-Agent** (sigma, high): This rule keys on the specific `MSAppHost/3.0` user-agent and filters out legitimate Microsoft destinations.
- **WWAHost_Spawning_Command_Shell** (sigma, high): This rule detects an extremely suspicious process parent-child relationship (`WWAHost.exe` -> shell).
- **Sideloading_AppX_Package_with_PowerShell** (sigma, high): This rule keys on specific keywords from the PowerShell command used for sideloading an AppX package.
- **Developer_Mode_Enabled_via_Registry** (sigma, medium): This rule detects the specific registry value being set to `1` to enable Developer Mode.
- **Developer_Mode_Enabled_via_Reg.exe** (sigma, medium): This rule detects the specific `reg.exe` command line used to enable Developer Mode.
- **WWAHost_Loading_Image_From_User_Profile** (sigma, medium): This rule detects the system process `WWAHost.exe` loading a DLL from an abnormal user-profile path.
