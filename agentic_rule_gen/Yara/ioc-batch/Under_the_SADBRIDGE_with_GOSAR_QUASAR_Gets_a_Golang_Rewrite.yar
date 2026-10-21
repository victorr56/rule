// Under the SADBRIDGE with GOSAR: QUASAR Gets a Golang Rewrite
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/under-the-sadbridge-with-gosar

import "hash"

rule IOC_Under_the_SADBRIDGE_with_GOSAR_QUASAR_Gets_a_Golang_Rewrite_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Under the SADBRIDGE with GOSAR: QUASAR Gets a Golang Rewrite. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/under-the-sadbridge-with-gosar"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "15af8c34e25268b79022d3434aa4b823ad9d34f3efc6a8124ecf0276700ecc39" or
        hash.sha256(0, filesize) == "accd651f58dd3f7eaaa06df051e4c09d2edac67bb046a2dcb262aa6db4291de7" or
        hash.sha256(0, filesize) == "7964a9f1732911e9e9b9e05cd7e997b0e4e2e14709490a1b657673011bc54210"
}

