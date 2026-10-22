// It’s a trap: Detecting a cryptominer on a popular website using Group-IB MXDR
// Source: group-ib | https://www.group-ib.com/blog/mxdr-cryptominer/

import "hash"

rule IOC_It_s_a_trap_Detecting_a_cryptominer_on_a_popular_website_using_Group_IB_MXDR_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: It’s a trap: Detecting a cryptominer on a popular website using Group-IB MXDR. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/mxdr-cryptominer/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "33251d1ec4f4ec19088c99d440bc4f0144259171" or
        hash.sha1(0, filesize) == "87968d094b1722e6253930c923a8f2828e667117" or
        hash.sha1(0, filesize) == "6bc997af69c702337c1d754558ecf5f70fb411b5"
}

