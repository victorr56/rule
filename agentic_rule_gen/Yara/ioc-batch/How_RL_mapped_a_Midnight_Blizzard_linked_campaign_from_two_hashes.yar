// How RL mapped a Midnight Blizzard-linked campaign from two hashes
// Source: reversinglabs | https://www.reversinglabs.com/blog/how-rl-mapped-a-midnight-blizzard-linked-campaign-from-two-hashes

import "hash"

rule IOC_How_RL_mapped_a_Midnight_Blizzard_linked_campaign_from_two_hashes_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: How RL mapped a Midnight Blizzard-linked campaign from two hashes. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "reversinglabs"
        reference   = "https://www.reversinglabs.com/blog/how-rl-mapped-a-midnight-blizzard-linked-campaign-from-two-hashes"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c" or
        hash.sha256(0, filesize) == "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593" or
        hash.sha256(0, filesize) == "28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3" or
        hash.sha256(0, filesize) == "ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25" or
        hash.sha256(0, filesize) == "20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38" or
        hash.sha256(0, filesize) == "5bc3c615da8dd7ef45e421d26a97644679ba0a0647b24efc96ebed8348f403d2" or
        hash.sha256(0, filesize) == "92cf0b883d220ba37f5ab378920fefdfdddc4fa76ee6c046696a7e5853a95c33" or
        hash.sha256(0, filesize) == "1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916" or
        hash.md5(0, filesize) == "c6f4df18cb880500f3921a179c3a3766" or
        hash.md5(0, filesize) == "fba867df17721879df9d8dcca68d6900" or
        hash.md5(0, filesize) == "4e2bd2c481372f7ab13b83b63b424e97" or
        hash.sha1(0, filesize) == "937e75e0e1c82eecab69e9b8ad481bd7e0845308" or
        hash.sha1(0, filesize) == "510af9bb00ff5d4a6856b1291af55db9f6e13551" or
        hash.sha1(0, filesize) == "6e5c658261f72fda92d475ac96f0213159af785d" or
        hash.sha1(0, filesize) == "154d8cfd9e304b6644216456759b7fd12daf85c1" or
        hash.sha1(0, filesize) == "9c5c539138df6cfcd854c55316bb527520025928"
}

