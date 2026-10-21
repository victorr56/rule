// Hidden in plain sight: How SVGs carry malicious scripts
// Source: reversinglabs | https://www.reversinglabs.com/blog/how-svgs-carry-dangerous-scripts

import "hash"

rule IOC_Hidden_in_plain_sight_How_SVGs_carry_malicious_scripts_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Hidden in plain sight: How SVGs carry malicious scripts. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "reversinglabs"
        reference   = "https://www.reversinglabs.com/blog/how-svgs-carry-dangerous-scripts"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "d9e4ae7bf23b5c6691156a6fa7fb128ea6890584" or
        hash.sha1(0, filesize) == "0d289ae3837acc7d076b770b6cec2a1d8b0fabf0" or
        hash.sha1(0, filesize) == "d632cad92dd560374eef427930cbef562b309067" or
        hash.sha1(0, filesize) == "c5329cfae6d94b2ba9dddaa20b1725a51104581c" or
        hash.sha1(0, filesize) == "771151e26a5e7d3198d3b28a919e802965482d39" or
        hash.sha1(0, filesize) == "effcc8433a07fb9e1b1cc2efa621487d62315177" or
        hash.sha1(0, filesize) == "31652250f9e4f67579a3e187806ba2cfad1792db" or
        hash.sha1(0, filesize) == "2b081fb89d88c93ee5339d33eb3200b69d5f3b8b"
}

