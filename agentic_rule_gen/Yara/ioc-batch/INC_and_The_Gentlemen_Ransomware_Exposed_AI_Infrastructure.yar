// INC and The Gentlemen Ransomware: Exposed AI Infrastructure
// Source: socradar | https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/

import "hash"

rule IOC_INC_and_The_Gentlemen_Ransomware_Exposed_AI_Infrastructure_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: INC and The Gentlemen Ransomware: Exposed AI Infrastructure. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "socradar"
        reference   = "https://socradar.io/blog/inc-gentlemen-ransomware-ai-infrastructure/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "ffca6aa96572743200f9f0040a3e435766f6d7c15d6a4c72045a0cbb4db72eb4" or
        hash.sha256(0, filesize) == "0ae4447d755593ee1931170d4187a07a29bf0690179acc39b7400a4c65cd07c5" or
        hash.sha256(0, filesize) == "14b711bd51096796ac6b38c30e3cced197831092956a4c6ff8d1f5ebb4432212" or
        hash.sha256(0, filesize) == "ec4ba1d570601eaa1474ab7cfffafcff218a717e44e8d2d22ed0573676b0463e" or
        hash.sha256(0, filesize) == "ca02f60942a43d8f8b973baa3231df1f8c26328750baa2ed8d4cf07335084ebb" or
        hash.sha256(0, filesize) == "ffd47c59a9960a293002c4fff481f613892599191356589eb7b6950ef7465918" or
        hash.sha256(0, filesize) == "70f28e18e7f4083cd542e6bff6b2682f3876c5ef4bcf4323aa22a6d03d4a8a82" or
        hash.sha256(0, filesize) == "7ad718a530a2913f775e62c656060af79ffde5c1f2c04138bcc068142f162a20" or
        hash.sha256(0, filesize) == "4286e7035096d002a0f90aca19b93504d7c69354cf0c76eb8b3c93bae2b7885a"
}

