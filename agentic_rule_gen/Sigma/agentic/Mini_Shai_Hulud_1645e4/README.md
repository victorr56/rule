# Mini Shai-Hulud

Source: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised

A credential-stealing worm that spreads via compromised npm and PyPi packages. The malware exfiltrates stolen cloud, CI/CD, and registry tokens over a typosquatted domain, the Session P2P network, or GitHub dead drops. A persistence mechanism on macOS/Linux wipes the user's home directory if a stolen GitHub token is revoked.

- **MiniShaiHuludMACOSLaunchAgent** (sigma, high): This rule detects the specific macOS persistence file path for Mini Shai-Hulud's wiper component.
- **MiniShaiHuludLinuxSystemdService** (sigma, high): This rule detects the specific Linux persistence file path for Mini Shai-Hulud's wiper component.
- **MiniShaiHuludPayloadExecution** (sigma, high): This rule detects the specific command line used to execute the malware's installer script.
- **MiniShaiHuludPayloadDownload** (sigma, high): This rule detects the download of a specific payload from a known malicious host, a high-confidence indicator.
- **MiniShaiHuludFileDrop** (sigma, medium): This rule detects a list of specific filenames dropped by different variants of the malware.
