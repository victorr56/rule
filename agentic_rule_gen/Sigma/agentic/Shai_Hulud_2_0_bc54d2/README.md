# Shai-Hulud 2.0

Source: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

Shai-Hulud 2.0 is a supply-chain attack campaign compromising hundreds of npm packages to steal secrets. The malware, executed via `preinstall` scripts, exfiltrates developer, CI/CD, and cloud credentials to public GitHub repositories. It also establishes a persistence backdoor by registering the compromised machine as a self-hosted GitHub runner.

- **ShaiHulud_Container_Breakout** (sigma, high): This rule detects a highly specific and malicious command line used for container breakout and privilege escalation, making it a high-confidence indicator.
- **ShaiHulud_Persistence_Workflow** (sigma, high): This rule detects the creation of a file at a specific, attacker-chosen path used for persistence, which is highly unlikely to be legitimate.
- **ShaiHulud_Exfiltration_Workflow** (sigma, high): This rule targets a specific file creation pattern (`formatter_*.yml`) in a sensitive directory, used by the malware for exfiltration.
- **ShaiHulud_Secret_Staging_File** (sigma, high): This rule detects the creation of files with specific, suspicious names (`actionsSecrets.json`, `truffleSecrets.json`) indicating credential staging.
- **ShaiHulud_Payload_File_Creation** (sigma, medium): This rule detects the creation of specific JavaScript filenames used as payloads, though they may overlap with legitimate `bun` toolkit files.
