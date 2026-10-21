# M-RED-TEAM

Source: https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions

The M-RED-TEAM campaign compromised the AsyncAPI project via a GitHub Actions 'pwn request' (pull_request_target checking out untrusted PR code), stealing an asyncapi-bot PAT to publish five malicious npm package versions under the @asyncapi namespace. The staged JavaScript payload runs on import, drops sync.js to a NodeJS folder, retrieves an encrypted bundle from IPFS, and installs a modular trojan framework with systemd persistence and multi-channel C2 (HTTP, Nostr, Ethereum, libp2p). It harvests browser credentials, SSH keys, npm/GitHub tokens, AWS credentials, macOS Keychain and crypto wallets.

- **SUSP_GitHub_Pwn_Request_M_RED_TEAM_Oct2026** (yara, high): This rule detects the specific GitHub Actions workflow misconfiguration exploited by M-RED-TEAM, combining the core vulnerability pattern with campaign-specific context.
- **MRedTeamPayloadDrop** (sigma, high): This rule detects the specific file path and name used by M-RED-TEAM's stage 2 payload, covering Windows, Linux, and macOS.
- **MRedTeamSystemdPersistence** (sigma, high): This rule detects the command used to enable the specific systemd user service for persistence, combining the process image with multiple specific arguments.
- **MRedTeamRentryExfiltration** (sigma, high): This rule detects access to the specific dead-drop URL path on rentry.co used by the malware for exfiltration.
