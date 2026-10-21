// A rigged game: ScarCruft compromises gaming platform in a supply-chain attack
// Source: welivesecurity | https://www.welivesecurity.com/en/eset-research/rigged-game-scarcruft-compromises-gaming-platform-supply-chain-attack/

import "hash"

rule IOC_A_rigged_game_ScarCruft_compromises_gaming_platform_in_a_supply_chain_attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: A rigged game: ScarCruft compromises gaming platform in a supply-chain attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "welivesecurity"
        reference   = "https://www.welivesecurity.com/en/eset-research/rigged-game-scarcruft-compromises-gaming-platform-supply-chain-attack/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "a8fe823d451d636d0a0366c0629ef5c3" or
        hash.sha1(0, filesize) == "b06110e0feb7592872e380b7e3b8f77d80dd1108"
}

