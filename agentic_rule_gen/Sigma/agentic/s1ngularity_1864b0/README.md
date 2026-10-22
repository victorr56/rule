# s1ngularity

Source: https://www.wiz.io/blog/s1ngularity-supply-chain-attack

s1ngularity is a malicious JavaScript post-install script (telemetry.js) distributed via compromised npm packages, primarily the Nx build system. It targets Linux and macOS developer systems to steal sensitive data including credentials, SSH keys, and crypto wallets. Stolen data is exfiltrated to attacker-created GitHub repositories on the victim's own account, which are later made public in a second phase.

- **S1ngularity_Exfiltration_via_GitHub_API** (sigma, high): This rule detects the specific GitHub API endpoint and filename used by S1ngularity for exfiltration, a high-confidence indicator.
- **S1ngularity_Persistence_via_Shell_Startup_Script** (sigma, high): This rule detects a highly specific command-line pattern used to establish persistence, combining the shell, the payload, and the target file type.
- **S1ngularity_Malicious_Javascript_Execution** (sigma, medium): This rule detects the execution of the specifically named malicious script by the node interpreter, a key step in the attack chain.
- **S1ngularity_Staging_File_Creation** (sigma, high): This rule keys on highly specific staging filenames written to the /tmp directory, which are strong indicators of S1ngularity's collection activity.
