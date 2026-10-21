// GroundPeony: Crawling with Malice
// Source: nao-sec | http://nao-sec.org/2023/08/groundpeony-crawling-with-malice.html

import "hash"

rule IOC_GroundPeony_Crawling_with_Malice_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: GroundPeony: Crawling with Malice. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "nao-sec"
        reference   = "http://nao-sec.org/2023/08/groundpeony-crawling-with-malice.html"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "1992b552bdaf93caeb470f94b4bf91e0157ba4a9bb92fb8430be946c0ddabdeb" or
        hash.sha256(0, filesize) == "425630cc8be2a7dc2626ccd927bb45e5d40c1cb606bb5b2a7e8928df010af7c9" or
        hash.sha256(0, filesize) == "fa6510a84929a0c49d91b3887189fca5a310129912d8e7d14fed062e9446af7e" or
        hash.sha256(0, filesize) == "142a027d78c7ab5b425c2b849b347952196b03618e4ad74452dbe2ed4e3f73cd"
}

