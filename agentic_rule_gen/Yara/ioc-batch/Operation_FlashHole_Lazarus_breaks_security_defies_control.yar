// Operation FlashHole: Lazarus breaks security, defies control
// Source: securelist | https://securelist.com/lazarus-operation-flashhole/121541/

import "hash"

rule IOC_Operation_FlashHole_Lazarus_breaks_security_defies_control_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Operation FlashHole: Lazarus breaks security, defies control. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/lazarus-operation-flashhole/121541/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "ec84d6cb2ae7974767aedac246b50a3e" or
        hash.md5(0, filesize) == "a28cba214058fcae2883d8cffc883abd" or
        hash.md5(0, filesize) == "c105d6b16f544582772de0159f24c00a" or
        hash.md5(0, filesize) == "2f8475a90a25624ed02f1d18d4e6d65d" or
        hash.md5(0, filesize) == "676fabe30a28b53925fba98e34b35986" or
        hash.md5(0, filesize) == "b4a7eff35f048f06fb0a2d7631f23a7d" or
        hash.md5(0, filesize) == "ff07641dc56914dd90ee0bd7404d7ad7"
}

