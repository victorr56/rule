# ARTEX

Source: https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/

An unnamed, likely Chinese-speaking financially motivated threat actor used ARTEX, a Chinese-developed open-source agentic pentesting tool, together with Claude Code and multiple LLMs to breach South Korean financial organizations between late September and early October 2026. Threat actor-controlled open directories on two servers exposed Claude Code session histories, ARTEX configuration files and memory files, revealing proxy-based C2 infrastructure. Detection should focus on the ARTEX instance path /.claude/CLAUDE.md on port 18899 and the identified proxy/threat-actor IP addresses.

- **ARTEX_C2_Proxy_IP_Activity** (sigma, high): This rule combines all actor-controlled and proxy IP addresses into a single network connection IOC rule.
- **ARTEX_DNS_Query_xcai_pro** (sigma, medium): This rule detects DNS queries for a domain associated with the attacker's LLM API proxy infrastructure.
