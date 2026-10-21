// Invisible miners: unveiling GHOSTENGINE’s crypto mining operations
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine

import "hash"

rule IOC_Invisible_miners_unveiling_GHOSTENGINE_s_crypto_mining_operations_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Invisible miners: unveiling GHOSTENGINE’s crypto mining operations. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "7c106041de7cc4c86cb9412a43cb7fc0a6ad2c76cfdb0e03a8ef98dd9e744442" or
        hash.sha256(0, filesize) == "2fe78941d74d35f721556697491a438bf3573094d7ac091b42e4f59ecbd25753" or
        hash.sha256(0, filesize) == "4b5229b3250c8c08b98cb710d6c056144271de099a57ae09f5d2097fc41bd4f1" or
        hash.sha256(0, filesize) == "2b33df9aff7cb99a782b252e8eb65ca49874a112986a1c49cd9971210597a8ae" or
        hash.sha256(0, filesize) == "3ced0552b9ecf3dfecd14cbcc3a0d246b10595d5048d7f0d4690e26ecccc1150" or
        hash.sha256(0, filesize) == "3b2724f3350cb5f017db361bd7aae49a8dbc6faa7506de6a4b8992ef3fd9d7ab" or
        hash.sha256(0, filesize) == "35eb368c14ad25e3b1c58579ebaeae71bdd8ef7f9ccecfc00474aa066b32a03f" or
        hash.sha256(0, filesize) == "786591953336594473d171e269c3617d7449876993b508daa9b96eedc12ea1ca" or
        hash.sha256(0, filesize) == "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5" or
        hash.sha256(0, filesize) == "aac7f8e174ba66d62620bd07613bac1947f996bb96b9627b42910a1db3d3e22b" or
        hash.sha256(0, filesize) == "6f3e913c93887a58e64da5070d96dc34d3265f456034446be89167584a0b347e" or
        hash.sha256(0, filesize) == "7c242a08ee2dfd5da8a4c6bc86231985e2c26c7b9931ad0b3ea4723e49ceb1c1" or
        hash.sha256(0, filesize) == "cc4384510576131c126db3caca027c5d159d032d33ef90ef30db0daa2a0c4104"
}

