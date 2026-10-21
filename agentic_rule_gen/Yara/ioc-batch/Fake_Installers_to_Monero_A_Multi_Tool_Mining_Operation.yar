// Fake Installers to Monero: A Multi-Tool Mining Operation
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero

import "hash"

rule IOC_Fake_Installers_to_Monero_A_Multi_Tool_Mining_Operation_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Fake Installers to Monero: A Multi-Tool Mining Operation. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/fake-installers-to-monero"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "460203070b5a928390b126fcd52c15ed3a668b77536faa6f0a0282cf1c157162" or
        hash.sha256(0, filesize) == "b8b7aecce2a4d00f209b1e4d30128ba6ef0f83bbdc05127f6f8ba97e7d6df291" or
        hash.sha256(0, filesize) == "9977b9185472c7d4be22c20f93bc401dd74bb47223957015a3261994d54c59fc" or
        hash.sha256(0, filesize) == "9fa23382820b1e781f3e05e9452176a72529395643f09080777fab7b9c6b1f5c" or
        hash.sha256(0, filesize) == "7bb0e91558244bcc79b6d7a4fe9d9882f11d3a99b70e1527aac979e27165f1d7" or
        hash.sha256(0, filesize) == "c6c4a9725653b585a9d65fc90698d4610579b289bcfb2539f7a5f7e64e69f2e4" or
        hash.sha256(0, filesize) == "a3f84aa1d15fd33506157c61368fd602d0b81f69aff6c69249bf833d217308bb" or
        hash.sha256(0, filesize) == "82c03866670b70047209c39153615512f7253f125a252fe3dcd828c6598fdf86" or
        hash.sha256(0, filesize) == "542d2267b40c160b693646bc852df34cc508281c4f6ed2693b98147dae293678" or
        hash.sha256(0, filesize) == "f84b00fc75f183c571c8f49fcc1d7e0241f538025db0f2daa4e2c5b9a6739049" or
        hash.sha256(0, filesize) == "0176ffaf278b9281aa207c59b858c8c0b6e38fdb13141f7ed391c9f8b2dc7630" or
        hash.sha256(0, filesize) == "9409f9c398645ddac096e3331d2782705b62e388a8ecb1c4e9d527616f0c6a9e" or
        hash.sha256(0, filesize) == "1f7441d72eff2e9403be1d9ce0bb07792793b2cb963f2601ecfdf8c91cd9af73" or
        hash.sha256(0, filesize) == "ce90cb3a9bfb8a276cb50462be932e063ed408af8c5591dd2c50f1c6d18c394c" or
        hash.sha256(0, filesize) == "bb48a52bae2ee8b98ee1888b3e7d05539c85b24548dd4c6acc08fbe5f0d7631a" or
        hash.sha256(0, filesize) == "6a01cc61f367d3bae34439f94ff3599fcccb66d05a8e000760626abb9886beac" or
        hash.sha256(0, filesize) == "e1e87d11079d33ec1a1c25629cbb747e56fe17071bde5fd8c982461b5baa80a4" or
        hash.md5(0, filesize) == "872d515ea17b4e6c3abca9752c706242"
}

