# Taurus Project

Source: https://www.group-ib.com/blog/cannibal-carders-fake-shops/

A large cybercriminal fraud operation, codenamed SPAGETTI, operates over 3,000 fake carding shop domains to scam other criminals. Victims are tricked into downloading the Taurus Project stealer, disguised as a 'protected app', which steals credentials from browsers, banking applications, and cryptocurrency wallets. The malware is an evolution of the PredatorTheThief stealer and exfiltrates data to a dedicated C2 infrastructure.

- **MAL_TaurusProject_Stealer_Oct2026** (yara, medium): This rule detects the Taurus Project stealer using a unique message string or a combination of associated filenames and domains from its distribution network.
- **Taurus_Project_Stealer_Execution** (sigma, high): This rule detects the execution of the Taurus Project stealer by its known executable names.
- **Taurus_Project_C2_And_Distribution_Domains** (sigma, high): This rule detects network traffic to domains known to be used for C2 and distribution by the Taurus Project.
- **Taurus_Project_Stealer_Archive_Creation** (sigma, medium): This rule detects the creation of a specific RAR file used to distribute the Taurus Project stealer.
