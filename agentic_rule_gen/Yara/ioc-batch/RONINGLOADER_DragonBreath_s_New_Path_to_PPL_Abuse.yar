// RONINGLOADER: DragonBreath’s New Path to PPL Abuse
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/roningloader

import "hash"

rule IOC_RONINGLOADER_DragonBreath_s_New_Path_to_PPL_Abuse_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: RONINGLOADER: DragonBreath’s New Path to PPL Abuse. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/roningloader"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b" or
        hash.sha256(0, filesize) == "82794015e2b40cc6e02d3c1d50241465c0cf2c2e4f0a7a2a8f880edaee203724" or
        hash.sha256(0, filesize) == "c65170be2bf4f0bd71b9044592c063eaa82f3d43fcbd8a81e30a959bcaad8ae5" or
        hash.sha256(0, filesize) == "2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5" or
        hash.sha256(0, filesize) == "1613a913d0384cbb958e9a8d6b00fffaf77c27d348ebc7886d6c563a6f22f2b7" or
        hash.sha256(0, filesize) == "395f835731d25803a791db984062dd5cfdcade6f95cc5d0f68d359af32f6258d" or
        hash.sha256(0, filesize) == "1c1528b546aa29be6614707cbe408cb4b46e8ed05bf3fe6b388b9f22a4ee37e2" or
        hash.sha256(0, filesize) == "4d5beb8efd4ade583c8ff730609f142550e8ed14c251bae1097c35a756ed39e6" or
        hash.sha256(0, filesize) == "96f401b80d3319f8285fa2bb7f0d66ca9055d349c044b78c27e339bcfb07cdf0" or
        hash.sha256(0, filesize) == "33b494eaaa6d7ed75eec74f8c8c866b6c42f59ca72b8517b3d4752c3313e617c" or
        hash.sha256(0, filesize) == "fc63f5dfc93f2358f4cba18cbdf99578fff5dac4cdd2de193a21f6041a0e01bc" or
        hash.sha256(0, filesize) == "fd4dd9904549c6655465331921a28330ad2b9ff1c99eb993edf2252001f1d107" or
        hash.sha256(0, filesize) == "3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33"
}

