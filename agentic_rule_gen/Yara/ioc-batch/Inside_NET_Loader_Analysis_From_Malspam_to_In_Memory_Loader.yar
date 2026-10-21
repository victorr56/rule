// Inside .NET Loader Analysis: From Malspam to In-Memory Loader
// Source: huntress | https://www.huntress.com/blog/malspam-to-loader-delivery-chain-analysis

import "hash"

rule IOC_Inside_NET_Loader_Analysis_From_Malspam_to_In_Memory_Loader_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Inside .NET Loader Analysis: From Malspam to In-Memory Loader. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/malspam-to-loader-delivery-chain-analysis"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d5b7247c497788cf0031ceb06e3df77a45fef59f1e49633dc7159816d64759b5" or
        hash.sha256(0, filesize) == "c61b1941cf756eb7551f7c661743802362728b785adc22e860d269713dfb01a6" or
        hash.sha256(0, filesize) == "c356aff1a01c2b0da472e584c8e3c8f875b9a24280435d42836a77b19f5a8c18" or
        hash.sha256(0, filesize) == "f1c3ebe78bd8c38559bf3cfcc9a9fa37d221e31780774a3787e26160a61f5348" or
        hash.sha256(0, filesize) == "e91fb249aa97be5c7931e430781167edfe7ba804720b5f643e6ab70b7e6e74dd"
}

