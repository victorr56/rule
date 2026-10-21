// Auditing the auditor: Unmasking Apex Accelerator
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages

import "hash"

rule IOC_Auditing_the_auditor_Unmasking_Apex_Accelerator_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Auditing the auditor: Unmasking Apex Accelerator. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "985829083f3937df6c82419216f7697afae0caac8efca6257a756066fe2c0abb" or
        hash.sha256(0, filesize) == "5ee7145061f05779f7f6f9b72e216713d17d53e183a92f408bfbbc44f2bfb95d" or
        hash.sha256(0, filesize) == "42a760b15fea7c9af718ee45386c1c3ea1bec9e30c95d16c287bcc8b2efdc72e" or
        hash.sha256(0, filesize) == "127ae4cad80b6605157ca2a1feada8a235e16aacc5d2119337a98115a4e13274" or
        hash.sha256(0, filesize) == "20f0a401676292d4ae34932e61f34afa97bcfc47ee517cda2afeb7222264a193" or
        hash.sha256(0, filesize) == "a50cdb508d13884630945a98eea0615b866d938eb0a16c5d958e6c8c181a6df8" or
        hash.sha256(0, filesize) == "68f5a00eafa8ecebf5d93328e0fec23b24d6f91808c8384db002946a13656c71" or
        hash.sha256(0, filesize) == "ee8cd9aba420f1b26b5d43e5bcdd6025a277b4946bb5daf76ab45c0e5f7ecd0b" or
        hash.sha256(0, filesize) == "ed5cb4af1d2cb067b8d23783ebf05d70278728462ba4f1bf29da0a3a41efc35e"
}

