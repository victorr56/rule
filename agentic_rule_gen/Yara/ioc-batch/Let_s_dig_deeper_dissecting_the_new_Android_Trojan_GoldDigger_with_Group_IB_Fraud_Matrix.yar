// Let’s dig deeper: dissecting the new Android Trojan GoldDigger with Group-IB Fraud Matrix
// Source: group-ib | https://www.group-ib.com/blog/golddigger-fraud-matrix/

import "hash"

rule IOC_Let_s_dig_deeper_dissecting_the_new_Android_Trojan_GoldDigger_with_Group_IB_Fraud_Matrix_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Let’s dig deeper: dissecting the new Android Trojan GoldDigger with Group-IB Fraud Matrix. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/golddigger-fraud-matrix/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c2b91a1d4b3d1dff21f280864c6c4d1ad79054ba6c68c8e453617320709230a1" or
        hash.sha256(0, filesize) == "139a5bcc92044e2e7c47aa28256218d92a37bed682b318a7b167abac6a1634bc" or
        hash.sha256(0, filesize) == "569626b0b6ef277cc1ad094a2f025d56b6f0e1ed9f9c2ccf1cc8ac492fb4e6a7" or
        hash.sha256(0, filesize) == "6171db5548941aff6c6873c1c292c631e0e3e8abc4d6a125e9359b72fcffbb60" or
        hash.sha256(0, filesize) == "0ffd769fec5314749c425374a79f02d3bbcd08eefba82c31283d972dd82414f5" or
        hash.sha256(0, filesize) == "70d90541639107710c6ef81d4055ea83b7df68b780d3ddac98f36f3f5242b6fb" or
        hash.sha256(0, filesize) == "71f104917dfb476ca9db0777d1f8b3cbc53d0740d84e5887e4700efee4bbfa95" or
        hash.sha256(0, filesize) == "dcc995261109549b69b0ccfd7dbc6beb922bbef1d4eb77923357c5df482baaae" or
        hash.sha256(0, filesize) == "b6a3b5d2f1953bce7d57f9e5836af74ace69636213c9d398429df003b7532172"
}

