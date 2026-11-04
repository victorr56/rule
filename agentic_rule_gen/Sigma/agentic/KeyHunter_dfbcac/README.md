# KeyHunter

Source: https://socradar.io/blog/keyhunter-operation-harvard-alumni-stanford-llm-key-data/

The leepsmarts actor conducts the KeyHunter operation, a multi-faceted campaign stealing LLM API keys and other credentials from misconfigured web services. The actor also runs an academic fraud scheme against universities and financial fraud operations using a cryptocurrency drainer and stolen credit card data. The campaign is heavily automated using AI agent frameworks like Hermes and OpenClaw, managed via Telegram.

- **Leepsmarts_Tooling_Deployment_Via_Git_Clone** (sigma, high): This rule detects a highly specific `git clone` command used by the actor to deploy their 'aipocket' tool.
- **Leepsmarts_Systemd_Scanner_Service** (sigma, high): This rule detects specific `systemctl` commands that manage the actor's custom `mscanner` services for reconnaissance.
- **Leepsmarts_CVE-2026-41940_cPanel_Exploit_Attempt** (sigma, high): This rule detects specific and distinct URI paths and queries used in the multi-stage CVE-2026-41940 exploit chain.
- **Leepsmarts_KeyHunter_C2_Domains** (sigma, high): This rule detects DNS queries for domains exclusively used by the leepsmarts actor for C2 and other malicious activities.
- **Leepsmarts_KeyHunter_C2_IP_Addresses** (sigma, high): This rule detects network connections to IP addresses identified as C2 and operational servers for the leepsmarts actor.
