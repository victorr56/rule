# SCKit

Source: https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/

SCKit is a malicious toolkit that abuses legitimate ScreenConnect remote-support software. After initial deployment, it installs an unauthorized secondary client for remote access, establishes persistence via scheduled tasks and Run keys, and deploys the RelayTrap component to deliver payloads to connecting IT support technicians. The toolkit also includes components for stealing browser authentication cookies to hijack web sessions.

- **MAL_SCKit_Scripts_Nov2026** (yara, medium): This rule detects SCKit scripts by combining unique short strings and supporting strings related to component names, C2 communication, and arguments, providing specific but flexible coverage.
- **SCKit_Persistence_Via_Run_Key_RelayTrapLiteAlert** (sigma, high): This rule detects a unique registry value 'RelayTrapLiteAlert' used by SCKit for persistence, which is a high-confidence indicator of compromise.
- **SCKit_Unauthorized_ScreenConnect_Client_Execution** (sigma, high): This rule combines the legitimate ScreenConnect process name with hardcoded malicious session IDs, making it a very high-precision detection for SCKit activity.
- **SCKit_C2_Domain_DNS_Query** (sigma, high): This rule lists specific, attacker-controlled domains associated with SCKit C2 infrastructure, providing a high-confidence alert on network activity.
- **SCKit_C2_IP_Address_Network_Connection** (sigma, high): This rule lists specific, attacker-controlled IP addresses associated with SCKit C2 infrastructure, providing a high-confidence alert on network activity.
- **SCKit_Toolkit_Archive_Extraction** (sigma, high): This rule keys on the unique directory name 'SCKitBundle' used for toolkit extraction, making it a precise indicator of initial SCKit staging activity.
