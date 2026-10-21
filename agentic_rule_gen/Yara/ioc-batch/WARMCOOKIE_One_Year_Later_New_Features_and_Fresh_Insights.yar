// WARMCOOKIE One Year Later: New Features and Fresh Insights
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/revisiting-warmcookie

import "hash"

rule IOC_WARMCOOKIE_One_Year_Later_New_Features_and_Fresh_Insights_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: WARMCOOKIE One Year Later: New Features and Fresh Insights. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/revisiting-warmcookie"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "8c5522c6f2ca22af8db14d404dbf5647a1eba13f2b0f73b0a06d8e304bd89cc0" or
        hash.sha256(0, filesize) == "c7bb97341d2f0b2a8cd327e688acb65eaefc1e01c61faaeba2bc1e4e5f0e6f6e" or
        hash.sha256(0, filesize) == "9d143e0be6e08534bb84f6c478b95be26867bef2985b1fe55f45a378fc3ccf2b" or
        hash.sha256(0, filesize) == "f4d2c9470b322af29b9188a3a590cbe85bacb9cc8fcd7c2e94d82271ded3f659" or
        hash.sha256(0, filesize) == "5bca7f1942e07e8c12ecd9c802ecdb96570dfaaa1f44a6753ebb9ffda0604cb4" or
        hash.sha256(0, filesize) == "b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6" or
        hash.sha256(0, filesize) == "e0de5a2549749aca818b94472e827e697dac5796f45edd85bc0ff6ef298c5555" or
        hash.sha256(0, filesize) == "169c30e06f12e33c12dc92b909b7b69ce77bcbfc2aca91c5c096dc0f1938fe76" or
        hash.sha1(0, filesize) == "e88727d4f95f0a366c2b3b4a742950a14eff04a4"
}

