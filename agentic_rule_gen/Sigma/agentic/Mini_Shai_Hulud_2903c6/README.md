# Mini-Shai-Hulud

Source: https://www.wiz.io/blog/mini-shai-hulud-teampcp-hits-antv-supply-chain

TeamPCP conducted a software supply chain campaign targeting NPM packages, GitHub Actions, and a VSCode extension. The malware, dubbed Mini-Shai-Hulud, establishes persistence via a Python backdoor which polls GitHub for commands. It is designed to harvest credentials and exfiltrate data to attacker-controlled GitHub repositories.

- **MAL_MiniShaiHulud_Backdoor_Oct2026** (yara, low): Keys on the SHA256 hash of a single known sample as no string evidence was provided.
- **MiniShaiHuludLinuxPersistence** (sigma, high): This rule detects a highly specific file path and name used for persistence by Mini-Shai-Hulud.
- **MiniShaiHuludMacOSPersistence** (sigma, high): This rule detects a highly specific file path and name used for persistence by Mini-Shai-Hulud.
- **MiniShaiHuludPythonBackdoor** (sigma, high): This rule detects the specific file path and name of the Python backdoor used by Mini-Shai-Hulud.
