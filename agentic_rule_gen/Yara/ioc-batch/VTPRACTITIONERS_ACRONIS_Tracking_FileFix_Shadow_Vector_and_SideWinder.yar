// VTPRACTITIONERS{ACRONIS}: Tracking FileFix, Shadow Vector, and SideWinder
// Source: virustotal | https://blog.virustotal.com/2025/11/vtpractitioners-acronis.html

import "hash"

rule IOC_VTPRACTITIONERS_ACRONIS_Tracking_FileFix_Shadow_Vector_and_SideWinder_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: VTPRACTITIONERS{ACRONIS}: Tracking FileFix, Shadow Vector, and SideWinder. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2025/11/vtpractitioners-acronis.html"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "1955c6914097477d5141f720c9e8fa44b4fe189e854da298d85090cbc338b35a" or
        hash.sha256(0, filesize) == "6d4a53da259c3c8c0903b1345efcf2fa0d50bc10c3c010a34f86263de466f5a1" or
        hash.sha256(0, filesize) == "2aae8e206dd068135b16ff87dfbb816053fc247a222aad0d34c9227e6ecf7b5b" or
        hash.sha256(0, filesize) == "4cfeab122e0a748c8600ccd14a186292f27a93b5ba74c58dfee838fe28765061" or
        hash.sha256(0, filesize) == "9bbbcb6eae33314b84f5e367f90e57f487d6abe72d6067adcb66eba896d7ce33"
}

