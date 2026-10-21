// NightMARE on 0xelm Street, a guided tour
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/nightmare-on-0xelm-street

import "hash"

rule IOC_NightMARE_on_0xelm_Street_a_guided_tour_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: NightMARE on 0xelm Street, a guided tour. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/nightmare-on-0xelm-street"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "26803ff0e079e43c413e10d9a62d344504a134d20ad37af9fd3eaf5c54848122"
}

