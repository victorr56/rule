# Agents Gone Wild: An AI-Orchestrated Global Campaign Against PaperCut NG/MF

Source: https://www.greynoise.io/blog/ai-orchestrated-campaign-against-papercut-ng-mf

A likely Russian-speaking actor used OpenAI Codex harnesses with a DeepSeek model to develop and mass-exploit PaperCut NG/MF (CVE-2026-81578, CVE-2026-82078), compromising at least 440 instances at 395 organizations in 48 countries. Post-exploitation relied on LSASS/registry hive harvesting, certutil staging, noPac and DCSync to reach Domain Admin in 12 victims, plus Ligolo-ng tunneling for persistence via 45.142.193.132 and 45.158.196.75. Detection should focus on the pc-*.hiv/pc-*.b64 staging paths, the reg save plus certutil -encode chains, Ligolo-ng agent drops under C:\ProgramData, and PaperCut pcp_*.txt web-root artifacts indicating successful exploitation.

- **PaperCutExploitActor_HiveDump_CommandLine** (sigma, high): This rule detects the specific command-line chain for dumping and encoding registry hives observed post-exploitation.
- **PaperCutExploitActor_Staged_Hive_Files** (sigma, high): This rule detects the specific staging file paths and patterns (`pc-*.hiv`, `pc-*.b64`) used for credential harvesting.
- **PaperCutExploitActor_LigoloNg_Variant** (sigma, high): This rule detects actor-specific file paths used to disguise and execute the Ligolo-ng tunneling tool for persistence.
- **PaperCut_Exploitation_WebRoot_Artifact** (sigma, high): This rule detects a high-confidence file artifact (`pcp_*.txt`) in the PaperCut web root, indicating successful exploitation.
