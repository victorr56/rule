# RustyAttr

Source: https://www.group-ib.com/blog/stealthy-attributes-of-apt-lazarus/

RustyAttr is a macOS trojan, attributed to the Lazarus group, that uses the Tauri framework to build its application. The malware's primary TTP is to conceal a malicious shell script within a custom macOS extended attribute to evade detection. Upon execution, the script is read from the attribute and run to download a second-stage payload, while a decoy PDF or error dialog is shown to the user.

- **APT_Lazarus_RustyAttr_macOS_Oct2026** (yara, medium): The rule keys on unique strings from the RustyAttr Mach-O binary, including long decoy URLs, error messages, and custom Tauri function names which are strong indicators. A combination of shorter but still specific strings provides a fallback detection mechanism.
- **Lazarus_RustyAttr_Shell_Execution_Pattern_macOS** (sigma, high): This rule detects the core execution behavior of RustyAttr's second stage with a highly specific command line pattern.
- **Lazarus_RustyAttr_C2_Domains** (sigma, high): This rule detects DNS queries for Lazarus-owned C2 domains, which are a high-fidelity indicator of compromise.
- **Lazarus_RustyAttr_C2_IPs** (sigma, high): This rule detects network connections to Lazarus-owned C2 IP addresses, a high-fidelity indicator of compromise.
- **Lazarus_RustyAttr_C2_URI_Pattern** (sigma, high): This rule combines actor-controlled domains with specific URI paths, making it a precise C2 detection.
- **Lazarus_RustyAttr_Decoy_Download_URL** (sigma, high): This rule detects a specific actor-controlled path on a public file hosting service used to deliver decoy documents.
- **Lazarus_RustyAttr_Lure_File_Creation** (sigma, medium): This rule detects the creation of lure files with highly specific names associated with this Lazarus campaign.
