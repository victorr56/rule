# Mini Shai Hulud

Source: https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm

Mini Shai Hulud is a supply chain campaign by TeamPCP targeting SAP-related and other npm packages. The malware uses a `preinstall` script to execute a credential stealer that harvests secrets from developer environments and CI/CD pipelines, including cloud, Kubernetes, and browser credentials. Data is exfiltrated to attacker-controlled GitHub repositories, with fallback mechanisms involving GitHub commit searches for configuration.

- **MiniShaiHulud_VSCode_Dropper_Creation** (sigma, high): This rule detects the creation of a key file used for persistence/execution in a path highly specific to the malware's TTP.
- **MiniShaiHulud_Claude_File_Creation** (sigma, high): This rule detects the creation of multiple malware artifacts in paths that are specific to the "Claude Code" IDE hook TTP.
