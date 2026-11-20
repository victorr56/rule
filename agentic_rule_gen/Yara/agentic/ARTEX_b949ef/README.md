# ARTEX

Source: https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks

ARTEX is an open-source Agentic Offensive Framework (AOF) that uses an LLM orchestrator to automate intrusions by chaining known vulnerabilities at machine speed. Its forks share a common Go-based engine, and detection should focus on behavioral fingerprints and infrastructure patterns rather than static signatures. Key indicators include unique User-Agent strings, specific LLM gateway abuse patterns, and a distinctive embedded favicon hash.

- **MAL_ARTEX_Agent_Nov2026** (yara, high): The rule keys on highly specific strings (Go import paths, unique User-Agents) and a combination of MurmurHash3 constants derived from embedded icons, making it precise for ARTEX and its forks.
