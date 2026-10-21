# "Mini" Shai-Hulud

Source: https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack

Malicious versions of keyv, cacheable and 400+ other npm packages in the Keyv/Cacheable ecosystem delivered a descendant of the "Mini" Shai-Hulud worm that harvests cloud, CI/CD, AI-tool and cryptocurrency credentials. The payload persists via Claude Code hooks and VS Code tasks.json, exfiltrates stolen data to attacker-created GitHub repositories, and resolves its C2 domains at runtime from an Ethereum smart contract.

- **MAL_Mini_Shai_Hulud_Oct2026** (yara, high): The rule keys on several highly unique and long strings reported as literals in malicious scripts.
- **Linux_Mini_Shaihulud_IDE_Hook_Persistence** (sigma, high): This rule detects the creation of malicious persistence scripts in specific IDE configuration directories, a unique behavior of this malware campaign.
- **Proxy_Mini_Shaihulud_C2_Discovery_Via_ETH_RPC** (sigma, high): This rule detects a novel C2 discovery TTP by keying on the specific Ethereum smart contract name, RPC method, and observed user-agent.
- **Linux_Mini_Shaihulud_NPM_Payload_File_Creation** (sigma, high): This rule detects the creation of a payload file at a very specific path associated with the compromised `keyv` npm package.
- **Dns_Mini_Shaihulud_C2_Domains** (sigma, high): This rule detects DNS queries for a list of domains exclusively controlled by the attacker for C2 and data exfiltration.
- **Linux_Mini_Shaihulud_Payload_Drop** (sigma, medium): This rule correlates the creation of a known payload filename (`math_init.js`) with the parent process being the Node.js or NPM interpreter.
- **Linux_Mini_Shaihulud_Lock_File_Creation** (sigma, medium): This rule detects the creation of a uniquely named temporary lock file used by the malware payload.
