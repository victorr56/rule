// MaaS Appeal: An Infostealer Rises From The Ashes
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/maas-appeal-an-infostealer-rises-from-the-ashes

import "hash"

rule IOC_MaaS_Appeal_An_Infostealer_Rises_From_The_Ashes_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: MaaS Appeal: An Infostealer Rises From The Ashes. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/maas-appeal-an-infostealer-rises-from-the-ashes"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ed164ee2eacad0eea9dc4fbe271ee2b2387b59929d73c843281a8d5e94c05d64" or
        hash.sha256(0, filesize) == "39f09771d70e96c7b760b3b6a30a015ec5fb6a9dd5bc1e2e609ddf073c2c853d" or
        hash.sha256(0, filesize) == "97393c27195c58f8e4acc9312a4c36818fe78f2ddce7ccba47f77a5ca42eab65"
}

