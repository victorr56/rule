// Soco404: Multiplatform Cryptomining Campaign Uses Fake Error Pages to Hide Payload
// Source: wiz | https://www.wiz.io/blog/soco404-multiplatform-cryptomining-campaign-uses-fake-error-pages-to-hide-payload

import "hash"

rule IOC_Soco404_Multiplatform_Cryptomining_Campaign_Uses_Fake_Error_Pages_to_Hide_Payload_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Soco404: Multiplatform Cryptomining Campaign Uses Fake Error Pages to Hide Payload. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/soco404-multiplatform-cryptomining-campaign-uses-fake-error-pages-to-hide-payload"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c9bb137d56fab7d52b3dbc85ae754b79d861a118bfb99566faaa342c978285ff" or
        hash.sha256(0, filesize) == "bac4b166dec1df8aa823a15136c82c8b50960b11a0c4da68b8d7dedcb0f3a794" or
        hash.sha256(0, filesize) == "c67e876d7b3ae5f3c4fd626d8ba62e77bd47dfdf51f7a4438edd64bd0f88ce3a" or
        hash.sha256(0, filesize) == "039caa15c1a54b49250717e68cd1a78a4be17b80e8062441c340eba0674e5926" or
        hash.sha256(0, filesize) == "0ad013c5166900b9c57a7ff771dbbf8b11f8a3be46a85cff6ced83ceb1a38f8d" or
        hash.sha256(0, filesize) == "5a8e5d7dfc7ccadf8b66fa8b04cf33010f0384072fc9b1fc79e7e1a65a0c701c" or
        hash.sha256(0, filesize) == "9055bcd42263d83943358f76b13cdf24079ef9db8a2167658089be5324279485" or
        hash.sha256(0, filesize) == "a1fbaee0915edd8568fcea9868fd511adb43faf93bd0abd63788a61febcff13b" or
        hash.sha256(0, filesize) == "09e7232ef9322792f6340cc637d3ba2292383c2d353196252bd7a3cf00f4ba0e" or
        hash.sha256(0, filesize) == "d62c4c621de5e6deee28454413c612cd99511aaa85f9722c1ebadc731d22cab2" or
        hash.sha256(0, filesize) == "e7fe0a5c6c198be8941d5a1be7c0669688c45751e9bf0d16a0ae6ae1d0e7a957" or
        hash.sha256(0, filesize) == "e69e55027bf64011599ae1283d15d157bfefed1c03e20fe72ecf7e90fd451e76" or
        hash.sha256(0, filesize) == "424f15e2509ed62c95d5637df0b519c40f73b3cbb00b7a8073ba89ddad7e5dc1" or
        hash.sha256(0, filesize) == "22abd35b6afd1909e6d71bd75b2ac23890e2675f9d40e403b0cfd4ed155a96f6" or
        hash.sha256(0, filesize) == "cbb9d5c601fca0b9b25ec914431abc35c45d5f4c2bbf18e14661aadd8e7e2f47" or
        hash.sha256(0, filesize) == "68bb9e294ba7f1b0426e16abbdb5c8f29daa8e8d98aee7a430ead97f2ffadd3a" or
        hash.sha256(0, filesize) == "8739f0189f64636fab1965bb066ba67a980ecabafd4307f4fb732ffdc154fa04" or
        hash.sha256(0, filesize) == "54303aa4f7b7ae3137f5f1368dba6b9b90f7826b8b18132ea495fff29f33f1e4" or
        hash.sha256(0, filesize) == "13e3cb74ad420c0770b9fedae617eaf312272db12035e4f64ebb606ac96f6ef0" or
        hash.sha256(0, filesize) == "498ecdfce65d739154b39703c63c8f4334066655e1cc8024c2716e280598cacc" or
        hash.sha256(0, filesize) == "8d06979a38ee5ef6f03817a1d16ab75171528cfaf8f743bfe64b45abd6c26142" or
        hash.sha256(0, filesize) == "bf038c13468a9b75278ea198c3d41d4ad4fc14e447d9dd0a94915ce2ab8132e5" or
        hash.sha256(0, filesize) == "a047e82948bf7c43281c975b9588bf5d4500fd671a5e25fc3f9206cbd1827dfd" or
        hash.sha256(0, filesize) == "5b224a091151661943e038066ef03f7b5bab055187f3b1b582dbfe392e74c921" or
        hash.sha256(0, filesize) == "0086fe6259af25f3b5a12d81080bed61938cc70ebdf480501acc1c10ac39c74a" or
        hash.sha256(0, filesize) == "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5" or
        hash.md5(0, filesize) == "14bf32e780601c6870811982648cf293"
}

