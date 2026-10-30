# ARTEX

Source: https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/

Storm-0940, a China-state aligned actor, uses the ARTEX AI framework to automate attacks at scale against cloud services. The campaign involved a supply chain compromise of ConnectWise, enabling password spraying and OAuth application abuse to gain privileged access to Microsoft 365 environments.

- **MAL_ARTEX_OAuth_GUIDs_Oct2026** (yara, medium): The rule keys on unique OAuth App ID GUIDs which are highly specific to Storm-0940's tooling.
- **Storm_0940_Suspicious_UA_With_Compromised_App** (sigma, high): This rule precisely targets attacker TTPs by requiring both a compromised AppID and a suspicious User-Agent, significantly reducing false positives.
- **Storm_0940_Signin_From_Associated_IP** (sigma, high): This rule detects sign-ins from IP addresses specifically linked to Storm-0940 infrastructure, providing a direct indicator of compromise.
