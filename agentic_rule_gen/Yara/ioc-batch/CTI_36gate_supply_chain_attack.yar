// 36gate: supply chain attack
// Source: group-ib | https://www.group-ib.com/blog/3cx-supply-chain-attack/

import "hash"

rule IOC_CTI_36gate_supply_chain_attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: 36gate: supply chain attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/3cx-supply-chain-attack/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983" or
        hash.sha256(0, filesize) == "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb" or
        hash.sha256(0, filesize) == "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02" or
        hash.sha256(0, filesize) == "253f3a53796f1b0fbe64f7b05ae1d66bc2b0773588d00c3d2bf08572a497fa59" or
        hash.sha256(0, filesize) == "82a2dafd6ce594f2cf8588f32585c71be2180fc4cf9a144e300b1692f3de5807" or
        hash.md5(0, filesize) == "ca8c0385ce2b8bdd19423c8b98a5924b" or
        hash.md5(0, filesize) == "27b134af30f4a86f177db2f2555fe01d" or
        hash.md5(0, filesize) == "5729fb29e3a7a90d2528e3357bd15a4b" or
        hash.md5(0, filesize) == "cb01ff4809638410a531400a66376fa3" or
        hash.md5(0, filesize) == "83cba55f180b0c100935137615e8d296" or
        hash.sha1(0, filesize) == "96910a3dbc194a7bf9a452afe8a35eceb904b6e4" or
        hash.sha1(0, filesize) == "ffccc3a29d1582989430e9b6c6d2bff1e3a3bb14" or
        hash.sha1(0, filesize) == "89827af650640c7042077be64dc643230d1f7482" or
        hash.sha1(0, filesize) == "b5de30a83084d6f27d902b96dd12e15c77d1f90b" or
        hash.sha1(0, filesize) == "8377fb40c76aa3ba3efae3d284fa51aa7748e010" or
        hash.sha1(0, filesize) == "11ae67704ea0b930b2cc966e6d07f8b898f1a7d2" or
        hash.sha1(0, filesize) == "f3487a1324f4c11b35504751a5527bc60eb95382" or
        hash.sha1(0, filesize) == "188754814b37927badc988b45b7c7f7d6b4c8dd3" or
        hash.sha1(0, filesize) == "ff3dd457c0d00d00d396fdf6ebe7c254fed2a91e" or
        hash.sha1(0, filesize) == "7a1d41c8e9e4bd19e0e360ec17e30c38e4f9ca0d"
}

