// SimpleHarm: Tracking MuddyWater’s infrastructure
// Source: group-ib | https://www.group-ib.com/blog/muddywater-infrastructure/

import "hash"

rule IOC_SimpleHarm_Tracking_MuddyWater_s_infrastructure_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: SimpleHarm: Tracking MuddyWater’s infrastructure. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/muddywater-infrastructure/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "2528838a609aa143769efb37dff45af723868d4ed33eb1ce0e2d6ce64b2a1507" or
        hash.md5(0, filesize) == "e7383c77c6f804cffac6c88651b7bce2" or
        hash.sha1(0, filesize) == "53ce7a2850e27465f3aae3cc2fae1a3ec1b6a640"
}

