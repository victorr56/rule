# Skilldrop

Source: https://blog.virustotal.com/2026/10/how-some-malicious-ai-skills-hide.html

Malicious AI skills, collectively identified as Skilldrop, hide instructions from human reviewers by concealing them within markdown files. Attackers use techniques such as excessive whitespace padding, HTML comments, and invisible Unicode characters to embed commands for data exfiltration, command execution, and persistent behavior modification.

- **SkilldropDownloaderCommandLine** (sigma, high): This rule detects a specific `curl ... | bash` command line identified in the report, providing a high-confidence indicator of compromise.
- **SkilldropC2AndExfiltrationDomains** (sigma, high): This rule detects network requests to domains specifically created for and used by the Skilldrop malware, making it a critical and precise indicator.
- **SkilldropC2AndExfiltrationURLs** (sigma, high): This rule combines actor-specific domains and URL paths, creating a highly specific pattern for Skilldrop C2, exfiltration, and payload download activity.
