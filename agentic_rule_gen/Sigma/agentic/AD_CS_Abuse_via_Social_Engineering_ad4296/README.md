# AD CS Abuse via Social Engineering

Source: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/

Threat actors use Microsoft Teams to impersonate IT support, socially engineering users into granting remote access via Quick Assist. They then stage portable runtimes like Bun, Python, or Java to discover and abuse Active Directory Certificate Services (AD CS) misconfigurations (ESC1, ESC8) for privilege escalation.

- **ADCSAbusePortableRuntimeExecution** (sigma, high): This rule combines the specific portable runtimes (`bun.exe`, `java.exe`) with the unique `KB...` staging directory pattern, making for a precise detection of the described TTP.
- **ADCSAbuseFileStaging** (sigma, medium): This rule detects the creation of any file in the actor's unique staging path pattern, providing an opportunity to catch tool deployment early in the attack chain.
