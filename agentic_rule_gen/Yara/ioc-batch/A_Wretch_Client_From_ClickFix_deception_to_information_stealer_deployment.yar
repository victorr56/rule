// A Wretch Client: From ClickFix deception to information stealer deployment
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/a-wretch-client

import "hash"

rule IOC_A_Wretch_Client_From_ClickFix_deception_to_information_stealer_deployment_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: A Wretch Client: From ClickFix deception to information stealer deployment. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/a-wretch-client"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "2ec47cbe6d03e6bdcccc63c936d1c8310c261755ae5485295fecac4836d7e56a" or
        hash.sha256(0, filesize) == "a8ba1e14249cdd9d806ef2d56bedd5fb09de920b6f78082d1af3634f4c136b90" or
        hash.sha256(0, filesize) == "f92b491d63bb77ed3b4c7741c8c15bdb7c44409f1f850c08dce170f5c8712d55" or
        hash.sha256(0, filesize) == "4dc5ba5014628ad0c85f6e8903de4dd3b49fed65796978988df8c128ba7e7de9" or
        hash.md5(0, filesize) == "82cddf3a9bff315d8fc708e5f5f85f20"
}

