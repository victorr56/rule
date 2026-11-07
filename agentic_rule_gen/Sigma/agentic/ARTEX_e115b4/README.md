# ARTEX

Source: https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/

The financially motivated actor Storm-3358 uses the agentic AI offensive framework ARTEX to target the financial sector. The framework automates scanning, exploitation of web vulnerabilities, and deployment of open-source remote access trojans (RATs) such as WISP, vshell, and AdaptixC2. ARTEX leverages common penetration testing tools like Nmap, curl, and Playwright to move at machine speed through victim networks.

- **Storm-3358_RAT_Execution** (sigma, high): This rule detects the execution of specific RATs by name, which are marked as high-specificity in the report.
- **ARTEX_User_Agent** (sigma, high): This rule is based on a unique User-Agent string directly associated with the ARTEX framework.
- **Storm-3358_C2_IPs** (sigma, high): This rule detects network connections to a list of specific IP addresses identified as C2 infrastructure for this threat.
