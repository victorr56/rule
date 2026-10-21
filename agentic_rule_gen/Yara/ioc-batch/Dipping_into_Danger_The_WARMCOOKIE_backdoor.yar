// Dipping into Danger: The WARMCOOKIE backdoor
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/dipping-into-danger

import "hash"

rule IOC_Dipping_into_Danger_The_WARMCOOKIE_backdoor_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Dipping into Danger: The WARMCOOKIE backdoor. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/dipping-into-danger"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ccde1ded028948f5cd3277d2d4af6b22fa33f53abde84ea2aa01f1872fad1d13" or
        hash.md5(0, filesize) == "5fb6dd81093a0d6812c17b12f139ce35"
}

