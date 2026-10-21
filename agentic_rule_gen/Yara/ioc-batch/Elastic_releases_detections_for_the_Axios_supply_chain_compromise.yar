// Elastic releases detections for the Axios supply chain compromise
// Source: elastic-security-labs | https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections

import "hash"

rule IOC_Elastic_releases_detections_for_the_Axios_supply_chain_compromise_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Elastic releases detections for the Axios supply chain compromise. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09" or
        hash.sha256(0, filesize) == "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7" or
        hash.sha256(0, filesize) == "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c" or
        hash.sha256(0, filesize) == "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff" or
        hash.sha1(0, filesize) == "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" or
        hash.sha1(0, filesize) == "07d889e2dadce6f3910dcbc253317d28ca61c766"
}

