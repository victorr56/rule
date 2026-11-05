// Binance heist: what we know, and what RL sees in TraderTraitor's toolkit
// Source: reversinglabs | https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit

import "hash"

rule IOC_Binance_heist_what_we_know_and_what_RL_sees_in_TraderTraitor_s_toolkit_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Binance heist: what we know, and what RL sees in TraderTraitor's toolkit. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "reversinglabs"
        reference   = "https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit"
        date        = "2026-11-05"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "62e988e9affcd000657bef4db47eb2e85c9a4cc42f4832780a02e19624e36e38" or
        hash.sha256(0, filesize) == "451b586ec9d3c997b319986a1177829653e8ae641c953c05ede6a38616f2da97" or
        hash.md5(0, filesize) == "9d88b4494c7bc27b10358b68a899ad54" or
        hash.md5(0, filesize) == "116f7189ed7b41f1b339a749d56e63be" or
        hash.md5(0, filesize) == "58fa0d651898446d5f5d2ed8a27a3330" or
        hash.md5(0, filesize) == "2621753691be9521288664bb551dfba6" or
        hash.md5(0, filesize) == "ad0b1b6d2c8b9d09d6473a4a299470ab" or
        hash.md5(0, filesize) == "4b8509cde757b5428e5f99c8dffe73ca" or
        hash.md5(0, filesize) == "3826dc7a9ba8bd5b1c143560c1530d89" or
        hash.md5(0, filesize) == "34a52e6a4d803e94fe497bab682abfd3"
}

