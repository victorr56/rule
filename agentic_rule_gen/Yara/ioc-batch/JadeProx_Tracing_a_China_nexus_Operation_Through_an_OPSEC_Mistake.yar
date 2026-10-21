// JadeProx: Tracing a China-nexus Operation Through an OPSEC Mistake
// Source: group-ib | https://www.group-ib.com/blog/jadeprox-china-nexus-triback-loader/

import "hash"

rule IOC_JadeProx_Tracing_a_China_nexus_Operation_Through_an_OPSEC_Mistake_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: JadeProx: Tracing a China-nexus Operation Through an OPSEC Mistake. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/jadeprox-china-nexus-triback-loader/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "853f760f76de3201b0af0e41f1f65fba" or
        hash.md5(0, filesize) == "e067ffea77875ae0dc13d4ce045931d3" or
        hash.md5(0, filesize) == "bb5c88de9e04e6306260b9f3a4498933" or
        hash.md5(0, filesize) == "35cdbf8a16da1245d574a0365cb87287" or
        hash.md5(0, filesize) == "0e6d22c2a81d29b1f9d8395d44e19e53" or
        hash.md5(0, filesize) == "d99392248bdd7e351e63ead6733638ba" or
        hash.md5(0, filesize) == "df1f03a2534480a4838f62339bcb90d8" or
        hash.md5(0, filesize) == "7840f30b395fac347f85b38633c2d08d" or
        hash.md5(0, filesize) == "9e01bf0e28c86435cfb1afaef44238e9" or
        hash.md5(0, filesize) == "f360afe51b499a036c7be8c0ecc4dc89" or
        hash.md5(0, filesize) == "39d4012e49f58092ec5cefed13dbbcfd" or
        hash.md5(0, filesize) == "ee5a2cdd4ce6ccb2e9279c9e13e8bd15" or
        hash.md5(0, filesize) == "b8053bcd04ce9d7d19c7f36830a9f26b" or
        hash.md5(0, filesize) == "0482d6053f96e6bde0a92af25497f3c0"
}

