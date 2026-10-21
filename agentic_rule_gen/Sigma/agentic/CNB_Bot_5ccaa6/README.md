# CNB Bot

Source: https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero

A financially motivated actor, REF1695, has been active since late 2023 deploying RATs (CNB Bot, PureRAT) and cryptominers (XMRig, PureMiner) via fake installers. Infection chains leverage Themida/WinLicense and .NET Reactor packing, establish persistence via scheduled tasks, and monetize through both cryptomining and CPA fraud. The operation is notable for its use of the previously undocumented CNB Bot and a custom XMRig loader with anti-analysis features.

- **MAL_REF1695_XMRig_Loader_Oct2026** (yara, medium): This rule keys on highly unique hardcoded strings (AES key, fallback config) and C2 artifacts specific to the custom .NET XMRig loader used by REF1695.
- **MAL_CNB_Bot_Oct2026** (yara, medium): This rule keys on a unique C2 URL path and a combination of other specific strings related to CNB Bot activity.
- **MAL_PureRAT_REF1695_Usage_Oct2026** (yara, medium): This rule keys on unique GitHub repository paths and usernames used by the REF1695 actor to host PureRAT payloads.
- **REF1695_CNB_Bot_Persistence_Creation** (sigma, high): This rule detects the creation of the specific "HostDataProcess" scheduled task used by CNB Bot.
- **REF1695_CNB_Bot_VBS_Launcher_Execution** (sigma, high): This rule detects the specific command line used to launch the CNB Bot VBScript component.
- **REF1695_PureRAT_Persistence_Creation** (sigma, high): This rule detects the creation of the specific "SVCConfig" scheduled task used by PureRAT.
- **REF1695_SilentCryptoMiner_Execution** (sigma, high): This rule detects SilentCryptoMiner execution based on its highly specific installation path.
- **REF1695_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains specifically associated with REF1695 malware.
- **REF1695_C2_URL_Paths** (sigma, high): This rule detects web requests to highly specific URL paths used for C2 and payload delivery.
