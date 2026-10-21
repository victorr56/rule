// PHANTOMPULSE: anatomy of a hijackable blockchain-C2 RAT
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole

import "hash"

rule IOC_PHANTOMPULSE_anatomy_of_a_hijackable_blockchain_C2_RAT_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: PHANTOMPULSE: anatomy of a hijackable blockchain-C2 RAT. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "def66275fa3baffb16e6e4ae0297861d9790ae7161fbc271a2ba05d121f13c70"
}

