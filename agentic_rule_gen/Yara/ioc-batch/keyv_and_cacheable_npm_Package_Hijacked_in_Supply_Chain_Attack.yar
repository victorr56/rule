// keyv and cacheable npm Package Hijacked in Supply Chain Attack
// Source: wiz | https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack

import "hash"

rule IOC_keyv_and_cacheable_npm_Package_Hijacked_in_Supply_Chain_Attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: keyv and cacheable npm Package Hijacked in Supply Chain Attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "35a672cf34b996b91f3e1c28cbf3a05a37e036e4" or
        hash.sha1(0, filesize) == "686aa40d0fc22c8d569494543a0f891f359f2f99" or
        hash.sha1(0, filesize) == "f525d52ceb966516686b482d3dc0137028cc6a63"
}

