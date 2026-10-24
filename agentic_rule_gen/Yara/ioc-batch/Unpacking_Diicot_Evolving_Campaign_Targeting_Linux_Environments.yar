// Unpacking Diicot - Evolving Campaign Targeting Linux Environments
// Source: wiz | https://www.wiz.io/blog/diicot-threat-group-malware-campaign

import "hash"

rule IOC_Unpacking_Diicot_Evolving_Campaign_Targeting_Linux_Environments_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unpacking Diicot - Evolving Campaign Targeting Linux Environments. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/diicot-threat-group-malware-campaign"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "a2101ec53fb0934b23f83c582d3a0bed9f66fd13" or
        hash.sha1(0, filesize) == "2ec6af460feabfe9ed37c1955ff266cff63f31ff" or
        hash.sha1(0, filesize) == "7940c6e29ab9cf6abe5e570f73eed93265962e1a" or
        hash.sha1(0, filesize) == "f657f695faf2cfd9f6f2188d154f7767da248b9e" or
        hash.sha1(0, filesize) == "a8a5d0223519590bb48e0b52102786623ec45511" or
        hash.sha1(0, filesize) == "7ece24f3b426169d720ab8353e07f0feb6dbc854" or
        hash.sha1(0, filesize) == "07f200ad0b5a03433a184b442dcd7a688e1ff7a7" or
        hash.sha1(0, filesize) == "970b45be172ffb9d3192a8d2d015b1c91b216107" or
        hash.sha1(0, filesize) == "f82b2df5e01abab70085a12388b3ec83c5e33ba1" or
        hash.sha1(0, filesize) == "e0e3456a0b3c06a33cbb4db1f7d1335b777cf107"
}

