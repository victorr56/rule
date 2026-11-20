# ARTEX

Source: https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex

ARTEX is an agentic offensive framework used by Storm-0940 that leverages a Large Language Model (LLM) to automate attacks in rapid bursts. It uses common offensive tools in parallel, has been observed performing Kerberoasting and SQL injection, and uses distinctive User-Agents like 'artex-enrich/1.0'. The report also details indicators for similar frameworks like CyberStrikeAI, PentAGI, and HexStrike.

- **Agentic_Offensive_Framework_User_Agent** (sigma, high): This rule detects a set of highly specific User-Agent strings associated with multiple agentic C2 frameworks.
- **PentAGI_Framework_C2_Domain** (sigma, high): This rule detects DNS queries for a C2 domain specifically associated with the PentAGI framework.
