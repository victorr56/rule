# ToxicSkills

Source: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/

ToxicSkills are malicious AI Agent Skills that instruct AI agents to perform harmful actions like credential theft and malware installation. They use obfuscated shell commands and prompt injection techniques within SKILL.md files to bypass security warnings and exfiltrate data, often targeting developer credentials or downloading further payloads.

- **ToxicSkills_Obfuscated_Command_Execution** (sigma, high): This rule detects a highly suspicious command obfuscation pattern by combining the shell process with `eval`, `echo`, and `base64 -d` arguments.
- **ToxicSkills_Malware_Unzip_And_Execution** (sigma, high): This rule is precise because it combines a shell process with a command line that includes a specific password (`infected123`) for `unzip` and a subsequent execution chain.
- **ToxicSkills_Malicious_URL_Access** (sigma, high): This rule detects network traffic to specific, known-malicious URLs, which is a high-confidence indicator of compromise.
- **ToxicSkills_Malicious_DNS_Query** (sigma, high): This rule detects DNS queries for a domain (`clawhub.ai`) specifically identified as hosting malicious content.
