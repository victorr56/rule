# FRUITSHELL, PLOTSAFE, HOLLOWCLAD, MANTLEMAZE, ROZESHELL (A3: AI-Analysis Evasion archetype)

Source: https://blog.talosintelligence.com/ignore-all-instructions-and-read-this-blog-the-state-of-ai-analysis-evasion-in-malware/

A3 (AI-Analysis Evasion) malware embeds plaintext natural-language instructions in binaries and scripts to steer LLM-assisted triage toward benign verdicts or refusals, seen across FRUITSHELL, PLOTSAFE, HOLLOWCLAD, MANTLEMAZE and ROZESHELL. Techniques progress from the verbatim 'For LLM and AI' comment to template generation, spraying instructions across nine model chat-template formats, intimidation/honeypot warnings, and fabricated copyright, government-contract and certification claims. The evasion text must be plaintext, making the embedded imperative strings themselves the primary detection surface, alongside MANTLEMAZE's iqvw64e.sys BYOVD PDB reference.

- **MAL_A3_Evasion_Technique_Oct2026** (yara, high): Keys on highly specific AI/LLM evasion and intimidation strings seen across FRUITSHELL, PLOTSAFE, and HOLLOWCLAD.
- **MAL_MANTLEMAZE_Loader_Oct2026** (yara, high): Keys on fabricated contract/NDA numbers and a BYOVD driver reference unique to MANTLEMAZE loaders.
- **A3_Evasion_Instruction_In_Script** (sigma, high): This rule detects highly specific imperative strings in PowerShell scripts designed to evade AI analysis, a core TTP from the report.
- **MANTLEMAZE_Service_Creation_For_Vulnerable_Driver** (sigma, high): This rule detects the specific command line used by MANTLEMAZE to create a malicious service for its BYOVD exploit, a high-confidence indicator.
- **MANTLEMAZE_Driver_Load_From_Non_Standard_Path** (sigma, high): This rule detects the loading of the vulnerable `iqvw64e.sys` driver from an unusual path, a strong indicator of an active BYOVD attack.
