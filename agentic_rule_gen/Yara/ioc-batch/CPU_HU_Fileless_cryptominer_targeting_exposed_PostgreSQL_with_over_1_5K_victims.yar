// CPU_HU: Fileless cryptominer targeting exposed PostgreSQL with over 1.5K victims
// Source: wiz | https://www.wiz.io/blog/postgresql-cryptomining

import "hash"

rule IOC_CPU_HU_Fileless_cryptominer_targeting_exposed_PostgreSQL_with_over_1_5K_victims_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: CPU_HU: Fileless cryptominer targeting exposed PostgreSQL with over 1.5K victims. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/postgresql-cryptomining"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "0b907eee9a85d39f8f0d7c503cc1f84a71c4de10" or
        hash.sha1(0, filesize) == "85198288e2ff1dad718cd84876a0b0d3173a641e" or
        hash.sha1(0, filesize) == "7ccfcacfa2a729494dece843e9c4d357f2eec780"
}

