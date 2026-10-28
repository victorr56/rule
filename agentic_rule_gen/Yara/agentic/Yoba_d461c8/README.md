# Yoba

Source: https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/

Yoba is a malware campaign that leverages fake GitHub repositories impersonating AI tools like ChatGPT and Claude to distribute its initial payload. The malware uses DLL sideloading against legitimate signed executables to deploy a multi-stage infection chain. The final loader uses a novel DGA seeded by a Telegram profile picture and DNS-over-HTTPS (DoH) to retrieve payloads, which has included the XMRig cryptominer.

- **MAL_Yoba_Oct2026** (yara, medium): The rule keys on verified constants from disassembly/hashing and unique (but unverified) strings from the report for the Yoba malware family, forming two distinct high-confidence detection patterns.
- **Yoba_DoH_C2_Communication** (sigma, high): This rule detects the unique DGA pattern used by Yoba within DoH TXT record queries, indicating a high-confidence C2 communication attempt.
- **Yoba_Persistence_Scheduled_Task** (sigma, high): This rule is based on the highly specific and unusual description field used by Yoba when creating its persistence scheduled task.
- **Yoba_Loader_DLL_Sideloading_Path** (sigma, high): This rule detects the creation of the specific Yoba loader DLL in its designated sideloading directory, a combination unique to this malware.
- **Yoba_DGA_DNS_Query** (sigma, high): This rule uses regular expressions to match the specific and structured DGA patterns used by Yoba for C2 communication.
- **Yoba_Dropper_Older_Variant_Path** (sigma, high): This rule keys on the unique combination of a typosquatted directory name ("Microsaft Difendir") and a specific DLL name, which is a strong indicator of this malware variant.
- **Yoba_XMRig_Tor_Bridge_Connection** (sigma, medium): This rule detects connections to known Tor bridge IPs used by the Yoba's XMRig payload, serving as a network-based IOC.
