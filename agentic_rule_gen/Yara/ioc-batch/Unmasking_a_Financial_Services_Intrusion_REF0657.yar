// Unmasking a Financial Services Intrusion: REF0657
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/unmasking-financial-services-intrusion-ref0657

import "hash"

rule IOC_Unmasking_a_Financial_Services_Intrusion_REF0657_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unmasking a Financial Services Intrusion: REF0657. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/unmasking-financial-services-intrusion-ref0657"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "bc90ef8121d20af264cc15b38dd1c3a866bfe5a9eb66064feb2a00d860a0e716" or
        hash.sha256(0, filesize) == "84b3bc58ec04ab272544d31f5e573c0dd7812b56df4fa445194e7466f280e16d"
}

