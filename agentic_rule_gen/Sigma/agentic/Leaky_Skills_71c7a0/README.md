# Leaky Skills

Source: https://snyk.io/blog/openclaw-skills-credential-leaks-research/

Leaky Skills are instructions for AI agents, typically in SKILL.md files, that cause them to insecurely handle sensitive data like API keys and PII. These skills force agents to pass secrets through LLM context windows, output them in logs, and store them in plaintext, creating exfiltration channels. The report highlights examples from the ClawHub marketplace, such as moltyverse-email and buy-anything, that demonstrate this "insecurity by design" pattern.

- **Potential_Credit_Card_Exfiltration_via_Curl** (sigma, high): This rule detects a highly specific and insecure command line pattern using `curl` to exfiltrate credit card data, making it a high-confidence indicator.
- **Leaked_API_Key_in_URL_Query_Parameter_to_Moltyverse** (sigma, high): This rule precisely targets a URL pattern known to leak API keys, combining a specific domain with a suspicious query string.
- **DNS_Query_for_Leaky_Skills_Associated_Domain** (sigma, high): This rule detects network traffic to domains specifically associated with the "Leaky Skills" ecosystem, serving as a strong indicator of related activity.
- **Clawhub_AI_Skill_Installation** (sigma, medium): This rule detects the use of the specific `clawhub` tool to install a component, indicating initial setup of the potentially insecure AI agent framework.
- **Clawdbot_AI_Agent_Session_Log_Created** (sigma, medium): This rule detects the creation of log files in a highly specific path structure (`/.clawdbot/.../sessions/`) associated with the Clawdbot framework.
- **Insecure_AI_Agent_Prompt_Log_Creation** (sigma, medium): This rule identifies the creation of markdown log files in a specific `/.prompt-log/` directory, which is a key artifact of the insecure `prompt-log` skill.
