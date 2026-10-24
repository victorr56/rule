// PerSwaysion Campaign
// Source: group-ib | https://www.group-ib.com/blog/perswaysion/

import "hash"

rule IOC_PerSwaysion_Campaign_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: PerSwaysion Campaign. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/perswaysion/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "a5e2a323bdb682660c9cd8b06e950f31" or
        hash.md5(0, filesize) == "e88a1b1823a36c944d71746cdefb5fdc"
}

