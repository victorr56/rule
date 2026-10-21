// Phishing Attacks Serve Browser-in-the-Browser Pages, Rogue RMM Persistence
// Source: huntress | https://www.huntress.com/blog/phishing-bitb-rmm-attacks

import "hash"

rule IOC_Phishing_Attacks_Serve_Browser_in_the_Browser_Pages_Rogue_RMM_Persistence_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Phishing Attacks Serve Browser-in-the-Browser Pages, Rogue RMM Persistence. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/phishing-bitb-rmm-attacks"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "41d2097e8ac636a478aa011e12128c03b3b9bb3c8efca43d3c4f214ac8b1f07b" or
        hash.sha256(0, filesize) == "fc96a04c615847f0fb1391f04d9d1aac7f78ddfb7d459168df0a4172b98354e2" or
        hash.sha256(0, filesize) == "9f5910d69a4fbc56ff1854e7e0df3199fbfddd7fe6b374f7d816fa6ae70ef991"
}

