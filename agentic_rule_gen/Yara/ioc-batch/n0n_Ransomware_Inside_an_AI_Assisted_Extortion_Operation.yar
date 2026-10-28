// n0n Ransomware: Inside an AI-Assisted Extortion Operation
// Source: socradar | https://socradar.io/blog/n0n-ransomware-ai-assisted-extortion/

import "hash"

rule IOC_n0n_Ransomware_Inside_an_AI_Assisted_Extortion_Operation_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: n0n Ransomware: Inside an AI-Assisted Extortion Operation. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "socradar"
        reference   = "https://socradar.io/blog/n0n-ransomware-ai-assisted-extortion/"
        date        = "2026-10-28"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d1fd3a8ac4ada74b8ccbcdf5134797acff401b7fb50e16549b337781dfe1a486" or
        hash.sha256(0, filesize) == "340172627cdf40927784956be784bd2b3f5d1584cb79cf31064f387bbe9acb28" or
        hash.sha256(0, filesize) == "886b3608d05069d314fa6300404de6627f96b13a95c5633f6c91dfc2a545ac87" or
        hash.sha1(0, filesize) == "dc82e9c22c4a06c6bc03701fce2b55f4f490c651"
}

