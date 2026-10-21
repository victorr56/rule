// Elastic catches DPRK passing out KANDYKORN
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn

import "hash"

rule IOC_Elastic_catches_DPRK_passing_out_KANDYKORN_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Elastic catches DPRK passing out KANDYKORN. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1" or
        hash.sha256(0, filesize) == "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940" or
        hash.sha256(0, filesize) == "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6" or
        hash.sha1(0, filesize) == "5555494485b460f1e2343dffaef9b94d01136320"
}

