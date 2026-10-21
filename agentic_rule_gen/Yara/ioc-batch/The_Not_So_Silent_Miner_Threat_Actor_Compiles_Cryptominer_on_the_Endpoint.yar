// The Not So Silent Miner: Threat Actor Compiles Cryptominer on the Endpoint
// Source: huntress | https://www.huntress.com/blog/threat-actor-compiles-cryptominer

import "hash"

rule IOC_The_Not_So_Silent_Miner_Threat_Actor_Compiles_Cryptominer_on_the_Endpoint_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Not So Silent Miner: Threat Actor Compiles Cryptominer on the Endpoint. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/threat-actor-compiles-cryptominer"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "0d202e16408770e8b6cceb14e1e3e72946b154bf881d27fe33d0060315b30dd1"
}

