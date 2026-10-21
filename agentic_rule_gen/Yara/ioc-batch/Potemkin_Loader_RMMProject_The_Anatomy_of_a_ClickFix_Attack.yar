// Potemkin Loader & RMMProject The Anatomy of a ClickFix Attack
// Source: huntress | https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack

import "hash"

rule IOC_Potemkin_Loader_RMMProject_The_Anatomy_of_a_ClickFix_Attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Potemkin Loader & RMMProject The Anatomy of a ClickFix Attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "3b7ae925e2d64522b4f69b56285b05aeca8c5aab5ab46a9c02c4fafb69d881ce" or
        hash.sha256(0, filesize) == "cd4e5e2c65b1660470d3446539ee68adf5faeece3eaeb46583623be9911ee145" or
        hash.sha256(0, filesize) == "2abe5dd3a057fdef935722e50e9251c272d29fd26113187b853a1f9a9cb89d9b" or
        hash.sha256(0, filesize) == "79f7b67ce8b39070f3e1c2b90fce0ce84134782a7dedcccc1edac197ee9e089b" or
        hash.sha256(0, filesize) == "2ada24dd6e517f37942b749c2bd57ddd97445e9853002cee70a0bc30d0b0ce3a" or
        hash.sha1(0, filesize) == "b3f2897f2bc797e5b9033faef8c81e92b01cb831" or
        hash.sha1(0, filesize) == "40b57c3622c1cbfd699207f71f2de5a8fe256893"
}

