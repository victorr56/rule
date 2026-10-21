// M-Red-Team: AsyncAPI Supply Chain Compromise via GitHub Actions
// Source: wiz | https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions

import "hash"

rule IOC_M_Red_Team_AsyncAPI_Supply_Chain_Compromise_via_GitHub_Actions_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: M-Red-Team: AsyncAPI Supply Chain Compromise via GitHub Actions. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "22bf76fe317ea6769bd38619bd440e42d119bd6b" or
        hash.sha1(0, filesize) == "a7e18d96efd3cdb127ef4cdcad9e3ad26c482bf2" or
        hash.sha1(0, filesize) == "9890950adcbc2478e7a080234f053214adbad44e" or
        hash.sha1(0, filesize) == "c70e105e212ff3c1daa04bb2a62507717f296b0b" or
        hash.sha1(0, filesize) == "c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5" or
        hash.sha1(0, filesize) == "12c37a86a0ed0bebe5d1d6a43e42f07860eac710" or
        hash.sha1(0, filesize) == "1969ab05d67b67fdcaa26240f738ccb077e1cd84" or
        hash.sha1(0, filesize) == "92d4c5413e4f7b258a114964101f9e1c6d64c6ba"
}

