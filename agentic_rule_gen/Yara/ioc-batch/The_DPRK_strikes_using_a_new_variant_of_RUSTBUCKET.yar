// The DPRK strikes using a new variant of RUSTBUCKET
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/DPRK-strikes-using-a-new-variant-of-rustbucket

import "hash"

rule IOC_The_DPRK_strikes_using_a_new_variant_of_RUSTBUCKET_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The DPRK strikes using a new variant of RUSTBUCKET. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/DPRK-strikes-using-a-new-variant-of-rustbucket"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747" or
        hash.sha256(0, filesize) == "1031871a8bb920033af87078e4a418ebd30a5d06152cd3c2c257aecdf8203ce6" or
        hash.sha256(0, filesize) == "788261d948177acfcfeb1f839053c8ee9f325bd6fb3f07637a7465acdbbef76a" or
        hash.sha256(0, filesize) == "7fccc871c889a4f4c13a977fdd5f062d6de23c3ffd27e72661c986fae6370387" or
        hash.sha256(0, filesize) == "ec8f97d5595d92ec678ffbf5ae1f60ce90e620088927f751c76935c46aa7dc41" or
        hash.sha256(0, filesize) == "de81e5246978775a45f3dbda43e2716aaa1b1c4399fe7d44f918fccecc4dd500" or
        hash.sha256(0, filesize) == "4f49514ab1794177a61c50c63b93b903c46f9b914c32ebe9c96aa3cbc1f99b16" or
        hash.sha256(0, filesize) == "fe8c0e881593cc3dfa7a66e314b12b322053c67cbc9b606d5a2c0a12f097ef69"
}

