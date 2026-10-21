// NightEagle targets Russian companies
// Source: securelist | https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/

import "hash"

rule IOC_NightEagle_targets_Russian_companies_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: NightEagle targets Russian companies. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "1dcafb7f8448683281106b06dd22409a" or
        hash.md5(0, filesize) == "1f3034b706c78b35d8e34044e68c693a" or
        hash.md5(0, filesize) == "3ecd1cd627d0340c92901a478a7caad8" or
        hash.md5(0, filesize) == "631fb131a56caf4ca0f287ed73e876ab" or
        hash.md5(0, filesize) == "4aa9fb1bf9223dfcdac920759bc7a3c7"
}

