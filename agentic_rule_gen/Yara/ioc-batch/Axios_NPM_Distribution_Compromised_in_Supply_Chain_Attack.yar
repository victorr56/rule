// Axios NPM Distribution Compromised in Supply Chain Attack
// Source: wiz | https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack

import "hash"

rule IOC_Axios_NPM_Distribution_Compromised_in_Supply_Chain_Attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Axios NPM Distribution Compromised in Supply Chain Attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101" or
        hash.sha256(0, filesize) == "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf" or
        hash.sha256(0, filesize) == "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09" or
        hash.sha256(0, filesize) == "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd" or
        hash.sha256(0, filesize) == "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff" or
        hash.sha256(0, filesize) == "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c" or
        hash.sha1(0, filesize) == "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" or
        hash.sha1(0, filesize) == "07d889e2dadce6f3910dcbc253317d28ca61c766"
}

