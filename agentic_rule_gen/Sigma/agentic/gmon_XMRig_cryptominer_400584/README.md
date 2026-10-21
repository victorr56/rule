# gmon / XMRig cryptominer

Source: https://www.wiz.io/blog/ai-infrastructure-honeypot

Honeypot telemetry shows attackers exploiting exposed AI infrastructure (LiteLLM MCP gateway auth bypass, MCP server test-endpoint command injection, blind prompt injection against agent frameworks) to gain unauthenticated RCE, then deploying Monero miners (gmon, XMRig) disguised with AI-tooling paths such as /app/data/.claude/ and /usr/src/node-red/. Post-exploitation focuses on AI-specific secrets, including querying the LiteLLM process's Python module state for the master key in memory and abusing the default master key sk-1234 for model enumeration.

- **APT_Qilin_LiteLLM_Exploit_Scripts_Oct2026** (yara, high): This rule keys on highly specific strings from Qilin's LiteLLM exploit scripts, including a unique prompt, C2 URL, CVEs, and API endpoints.
- **QilinActorLiteLLMMasterKeyExtraction** (sigma, high): This rule keys on a highly specific Python one-liner used to dump secrets from the LiteLLM framework in memory.
- **QilinActorGmonMinerExecution** (sigma, high): This rule detects the execution of the `gmon` miner from the specific `/tmp/.dbus-cache/` staging path.
- **QilinActorMinerMasqueradingInToolingPaths** (sigma, high): This rule detects miner execution from unusual paths designed to masquerade as Node-RED or Claude AI components.
- **QilinActorBase64EncodedPayloadExecution** (sigma, high): This rule detects a specific base64-encoded command string used by the actor for payload execution via prompt injection.
- **QilinActorC2AndStagingNetworkConnection** (sigma, high): This rule detects network connections to IP addresses known to be used by this campaign for C2 and staging.
