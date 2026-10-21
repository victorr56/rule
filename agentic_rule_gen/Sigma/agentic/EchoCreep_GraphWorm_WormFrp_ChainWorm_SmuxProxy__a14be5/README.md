# EchoCreep, GraphWorm, WormFrp, ChainWorm, SmuxProxy, WormSocket (Webworm toolset)

Source: https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/

Webworm is a China-aligned APT that has shifted from McRat/Trochilus backdoors to stealthy, chained proxy tooling and added two new backdoors in 2025: EchoCreep (Discord C&C) and GraphWorm (Microsoft Graph API/OneDrive C&C). The group stages tools in a forked WordPress GitHub repository and retrieves WormFrp configurations from a compromised Amazon S3 bucket, using open-source scanners (dirsearch, nuclei) for reconnaissance. This profile captures the backdoor command strings, proxy artifacts, and C2/proxy infrastructure reported by ESET.

- **APT_Webworm_EchoCreep_Oct2026** (yara, medium): This rule keys on highly specific command strings and unique IDs found in logs of the EchoCreep backdoor, providing strong anchors for detection.
- **APT_Webworm_GraphWorm_Oct2026** (yara, low): This rule detects the GraphWorm backdoor by combining unique filenames, commands, and API paths, most of which are sourced from prose in the report.
- **Webworm_C2_IPs** (sigma, high): This rule detects connections to a list of specific C2/proxy IP addresses exclusively used by Webworm.
- **Webworm_Persistence_Via_Scheduled_Task** (sigma, high): This rule detects the creation of a scheduled task using the specific name "MicrosoftSSHUpdate" employed by Webworm.
- **Webworm_Staging_Repository_Access** (sigma, high): This rule detects access to a unique GitHub repository path used by Webworm to stage tools.
- **Webworm_EchoCreep_VBS_Execution** (sigma, high): This rule keys on the specific, hardcoded path and filename from an observed EchoCreep test command.
- **Webworm_Reconnaissance_Dirsearch** (sigma, medium): This rule detects the `dirsearch` process combined with a highly specific command-line argument string.
