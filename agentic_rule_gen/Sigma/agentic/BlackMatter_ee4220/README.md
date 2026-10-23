# BlackMatter

Source: https://www.group-ib.com/blog/blackmatter2/

BlackMatter is a Ransomware-as-a-Service (RaaS) operation considered to be the successor to DarkSide. It features distinct ransomware variants for Windows and Linux, utilizing ChaCha20 and HC-256 encryption respectively. The malware is known for its configurable nature, targeting of critical infrastructure, and high ransom demands communicated via Tor-based chat rooms.

- **MAL_BlackMatter_Windows_Oct2026** (yara, medium): This rule keys on unique code sequences and a PRNG seed string from BlackMatter Windows variants, supported by a combination of configuration and API-related strings. The `1 of ($x*)` condition provides high-confidence matches on strong anchors, while the `3 of ($s*)` condition offers broader detection for variants that might not share the same code but reuse configuration strings.
- **MAL_BlackMatter_Linux_Oct2026** (yara, medium): This rule detects the Linux variant of BlackMatter ransomware using a very specific 39-byte code sequence and a unique 18-byte configuration string as strong anchors. A fallback condition using a combination of other distinctive section names and configuration keys provides resilience against minor variations.
- **blackmatter_ransom_note** (sigma, high): The rule detects the creation of files matching the specific BlackMatter ransom note pattern `[VICTIM_ID].README.txt`.
- **blackmatter_c2_domains** (sigma, high): This rule detects DNS queries for known BlackMatter C2 and payment portal domains.
- **blackmatter_c2_urls** (sigma, high): This rule detects proxy events for URLs associated with BlackMatter's Tor-based payment portals.
