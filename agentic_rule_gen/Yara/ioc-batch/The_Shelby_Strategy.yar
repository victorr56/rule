// The Shelby Strategy
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/the-shelby-strategy

import "hash"

rule IOC_The_Shelby_Strategy_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Shelby Strategy. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/the-shelby-strategy"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "feb5d225fa38efe2a627ddfbe9654bf59c171ac0742cd565b7a5f22b45a4cc3a" or
        hash.sha256(0, filesize) == "5c384109d3e578a0107e8518bcb91cd63f6926f0c0d0e01525d34a734445685c" or
        hash.sha256(0, filesize) == "0e25efeb4e3304815f9e51c1d9bd3a2e2a23ece3a32f0b47f829536f71ead17a" or
        hash.sha256(0, filesize) == "0354862d83a61c8e69adc3e65f6e5c921523eff829ef1b169e4f0f143b04091f" or
        hash.sha256(0, filesize) == "fb8d4c24bcfd853edb15c5c4096723b239f03255f17cec42f2d881f5f31b6025" or
        hash.sha256(0, filesize) == "472e685e7994f51bbb259be9c61f01b8b8f35d20030f03215ce205993dbad7f5" or
        hash.sha256(0, filesize) == "e51c6f0fbc5a7e0b03a0d6e1e1d26ab566d606b551c785bf882e9a02f04c862b"
}

