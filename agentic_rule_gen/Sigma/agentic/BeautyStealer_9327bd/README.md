# BeautyStealer

Source: https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/

Gorbag is a Russia-aligned threat actor targeting Ukrainian entities since at least February 2025. It uses a simple toolset, including the custom BeautyStealer infostealer and Prime ReverseShell, for rapid intelligence collection and exfiltration, possibly acting as an initial access broker.

- **Gorbag_C2_Infrastructure_Connection** (sigma, high): This rule detects network connections to IP addresses hardcoded in Gorbag's malware for C2 and exfiltration.
