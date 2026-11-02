// CyberStrikeAI in the wild: the use of AI in real-world attacks on organizations
// Source: securelist | https://securelist.com/tr/cyberstrikeai-attacks/121715/

import "hash"

rule IOC_CyberStrikeAI_in_the_wild_the_use_of_AI_in_real_world_attacks_on_organizations_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: CyberStrikeAI in the wild: the use of AI in real-world attacks on organizations. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/tr/cyberstrikeai-attacks/121715/"
        date        = "2026-11-02"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "d726a8b4886c636f76ca6d30ef6a6ff4" or
        hash.md5(0, filesize) == "2770562d104391b92b42671c270079bb" or
        hash.md5(0, filesize) == "09e1da2afa1216ecc55648ec8e122d2a" or
        hash.md5(0, filesize) == "805b9e4ae74c903787416800999b8418" or
        hash.md5(0, filesize) == "29efd64dd3c7fe1e2b022b7ad73a1ba5" or
        hash.md5(0, filesize) == "74f57b3e897a4960dcdd5b7e8a54f9df" or
        hash.md5(0, filesize) == "0bbd08af95f877f1d568b03de2eb76b4"
}

