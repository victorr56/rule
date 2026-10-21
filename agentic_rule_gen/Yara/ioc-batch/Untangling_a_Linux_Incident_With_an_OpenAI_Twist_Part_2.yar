// Untangling a Linux Incident With an OpenAI Twist (Part 2)
// Source: huntress | https://www.huntress.com/blog/codex-part-two

import "hash"

rule IOC_Untangling_a_Linux_Incident_With_an_OpenAI_Twist_Part_2_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Untangling a Linux Incident With an OpenAI Twist (Part 2). Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/codex-part-two"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "781c19b56fbdb17284707f9026e107f639e5447df7df3b248a5d5a50c4b0806c"
}

