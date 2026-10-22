# Gamaredon

Source: https://www.elastic.co/security-labs/threat-command/playing-defense-against-gamaredon-group

Gamaredon Group targets Ukrainian entities via spearphishing with malicious documents using remote template injection. The macro-enabled templates execute VBA to disable security warnings, persist via a VBScript in the startup folder, and communicate with Dynamic DNS-based C2 infrastructure. The campaign has observed ties to the Pteranodon backdoor.

- **APT_Gamaredon_Pteranodon_Payload_Oct2026** (yara, medium): This rule keys on highly specific VBA code fragments and a C2 path found in Gamaredon's Pteranodon malware. These strings are long and distinctive, making them strong indicators.
- **gamaredon_persistence_startup_vbs** (sigma, high): This rule detects the specific persistence file path and name created by a Microsoft Office parent process, making it a high-fidelity indicator for this Gamaredon TTP.
- **gamaredon_pteranodon_file_drop** (sigma, high): This rule is based on highly specific filenames dropped by the Pteranodon backdoor, which are unlikely to be seen in legitimate operations.
- **gamaredon_macro_security_bypass** (sigma, medium): This rule detects a common macro-based attack behavior by combining the target registry keys with the parent process (Office suite) and the specific value being set.
- **gamaredon_c2_ips** (sigma, high): This rule is based on a list of specific, high-confidence C2 IP addresses associated with Gamaredon Group campaigns.
- **gamaredon_c2_uri_path** (sigma, high): This rule detects a highly specific and unusual URI path, `//posolreboot.php`, used for C2 check-ins by Gamaredon malware.
