# Aokigahara

Source: https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/

Aokigahara is a new infostealer notable for targeting AI applications and developer tools alongside traditional targets like browsers and cryptocurrency wallets. It exfiltrates credentials, session data, and configuration files from tools such as ChatGPT Desktop, GitHub Copilot, and various cloud CLI tools. The malware uses a custom C2 protocol over HTTP with AES-GCM encrypted data and X25519 for key exchange.

- **MAL_Aokigahara_Stealer_Oct2026** (yara, medium): The rule keys on unique strings like the malware's name ("aokigahara", "kamidere"), a special PE section name (".stgcfg"), a config marker ("STGC"), and C2 paths. The condition requires multiple indicators, ensuring high precision.
- **Aokigahara_Infostealer_C2_Communication** (sigma, high): This rule is precise by combining a legitimate but specific User-Agent with three unique C2 URI paths.
- **Aokigahara_Infostealer_Sensitive_File_Access** (sigma, medium): This rule keys on a list of highly specific file paths targeted by Aokigahara for credential theft.
- **Aokigahara_Infostealer_Named_Pipe** (sigma, high): This rule detects the creation of a named pipe with the specific and unique prefix "akg_".
- **Aokigahara_Infostealer_C2_Domain_Query** (sigma, high): This rule is based on a list of domains observed to be used exclusively by Aokigahara C2 infrastructure.
- **Aokigahara_Infostealer_C2_Connection** (sigma, high): This rule detects connections to a specific IP and port combination used by Aokigahara C2 servers.
