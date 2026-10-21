# Aoki (Aokigahara) / Infostealer.Aoki

Source: https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting

Aoki (aka Aokigahara) is a recently emerged information stealer that harvests credentials and session files for AI coding assistants such as Claude, Codex, Cursor, Codeium and Gemini, alongside browser, wallet, messaging and password-manager data. It has no backdoor command list: it collects available data and exfiltrates it over HTTP to its C2 server via a /gate endpoint. Symantec detects the family as Infostealer.Aoki.

- **MAL_Aoki_Infostealer_Oct2026** (yara, medium): This rule detects the Aoki infostealer by matching the unique family name 'Aokigahara' and a supporting string like the C2 path or a detection alias.
- **AokiExfiltrationToGateEndpoint** (sigma, high): This rule is highly precise by combining known Aoki C2 domains with the specific `/gate` exfiltration path.
- **AokiAccessToClaudeAIConfig** (sigma, high): This rule keys on access to the highly specific `.claude.json` file by a process in a user directory, a common execution location for malware.
- **InfostealerAccessingBrowserCookies** (sigma, high): This rule detects a core infostealer behavior: a process not in a standard program directory accessing sensitive browser cookie databases.
- **AokiC2DNSQueries** (sigma, high): This rule detects DNS lookups for domains exclusively associated with Aoki C2 infrastructure.
