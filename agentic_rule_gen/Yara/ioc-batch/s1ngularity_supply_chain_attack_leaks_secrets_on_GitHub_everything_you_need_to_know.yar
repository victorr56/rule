// s1ngularity: supply chain attack leaks secrets on GitHub: everything you need to know
// Source: wiz | https://www.wiz.io/blog/s1ngularity-supply-chain-attack

import "hash"

rule IOC_s1ngularity_supply_chain_attack_leaks_secrets_on_GitHub_everything_you_need_to_know_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: s1ngularity: supply chain attack leaks secrets on GitHub: everything you need to know. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/s1ngularity-supply-chain-attack"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "2379ac0e03b1a67c4ca5693136eff4945e644a91" or
        hash.sha1(0, filesize) == "e5d1f3c45ee7cca6ae59cf64e0573050bbe136ec" or
        hash.sha1(0, filesize) == "b4f20b39aa6df1002872f07973024d85aa49abaf" or
        hash.sha1(0, filesize) == "d2438106211ebd12c4f0a248848bc9864c97a3c0"
}

