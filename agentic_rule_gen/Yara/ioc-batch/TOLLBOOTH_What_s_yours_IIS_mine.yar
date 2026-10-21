// TOLLBOOTH: What's yours, IIS mine
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/tollbooth

import "hash"

rule IOC_TOLLBOOTH_What_s_yours_IIS_mine_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: TOLLBOOTH: What's yours, IIS mine. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/tollbooth"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "913431f1d36ee843886bb052bfc89c0e5db903c673b5e6894c49aabc19f1e2fc" or
        hash.sha256(0, filesize) == "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1" or
        hash.sha256(0, filesize) == "c1ca053e3c346513bac332b5740848ed9c496895201abc734f2de131ec1b9fb2" or
        hash.sha256(0, filesize) == "c348996e27fc14e3dce8a2a476d22e52c6b97bf24dd9ed165890caf88154edd2" or
        hash.sha256(0, filesize) == "82b7f077021df9dc2cf1db802ed48e0dec8f6fa39a34e3f2ade2f0b63a1b5788" or
        hash.sha256(0, filesize) == "bd2de6ca6c561cec1c1c525e7853f6f73bf6f2406198cd104ecb2ad00859f7d3" or
        hash.sha256(0, filesize) == "915441b7d7ddb7d885ecfe75b11eed512079b49875fc288cd65b023ce1e05964" or
        hash.sha256(0, filesize) == "bae5a7722814948fbba197e9b0f8ec5a6fe8328c7078c3adcca0022a533a84fe" or
        hash.sha256(0, filesize) == "230b84398e873938bbcc7e4a1a358bde4345385d58eb45c1726cee22028026e9"
}

