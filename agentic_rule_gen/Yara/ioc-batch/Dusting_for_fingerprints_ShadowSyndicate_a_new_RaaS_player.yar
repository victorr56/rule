// Dusting for fingerprints: ShadowSyndicate, a new RaaS player?
// Source: group-ib | https://www.group-ib.com/blog/shadowsyndicate-raas/

import "hash"

rule IOC_Dusting_for_fingerprints_ShadowSyndicate_a_new_RaaS_player_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Dusting for fingerprints: ShadowSyndicate, a new RaaS player?. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/shadowsyndicate-raas/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "b54cce689e9139e824b6e51a84a7a103" or
        hash.md5(0, filesize) == "9bd79ffaeb8de31c9813b3ce51b30488" or
        hash.md5(0, filesize) == "96ea77a1a901e38aac8b9d5772d3d765"
}

