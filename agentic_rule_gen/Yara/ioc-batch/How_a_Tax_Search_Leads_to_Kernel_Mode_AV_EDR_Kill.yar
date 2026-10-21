// How a Tax Search Leads to Kernel-Mode AV/EDR Kill
// Source: huntress | https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill

import "hash"

rule IOC_How_a_Tax_Search_Leads_to_Kernel_Mode_AV_EDR_Kill_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: How a Tax Search Leads to Kernel-Mode AV/EDR Kill. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531" or
        hash.sha256(0, filesize) == "7509365935fc1bfadba20656698d3a29051031635419043bc2bc45116106e026" or
        hash.sha256(0, filesize) == "2b409a265f571dccde6ef4860831c1b03d5418d1951f97925315dc5b0891da04" or
        hash.sha256(0, filesize) == "0821661e715fe64bb39f4fece277737a48fd6839edd40ec8a4a39bf04cea8524" or
        hash.sha256(0, filesize) == "033f42102362a8d8d4bdba870599eb5e0c893d8fd8dd4bc2a4b446cbbeb59b99" or
        hash.sha256(0, filesize) == "5abe477517f51d81061d2e69a9adebdcda80d36667d0afabe103fda4802d33db" or
        hash.sha256(0, filesize) == "28278b8c85c832417f9860fe8ea3ddbb9ff1d5860317db4813227a3a52b7c7cc"
}

