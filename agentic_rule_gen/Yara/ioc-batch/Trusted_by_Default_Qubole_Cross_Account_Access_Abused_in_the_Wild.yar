// Trusted by Default: Qubole Cross-Account Access Abused in the Wild
// Source: wiz | https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild

import "hash"

rule IOC_Trusted_by_Default_Qubole_Cross_Account_Access_Abused_in_the_Wild_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Trusted by Default: Qubole Cross-Account Access Abused in the Wild. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild"
        date        = "2026-11-10"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "65f061281c9a712e9502793dc4c5035cae490b84da05f7d4223cefa65ad396e4" or
        hash.md5(0, filesize) == "086d4a83181971e883c53a4c44f46da2" or
        hash.sha1(0, filesize) == "1c7437dac21630f53c0b888b50662c6487e23fd7"
}

