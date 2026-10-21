// ValleyRAT masquerading as adware
// Source: securelist | https://securelist.com/valleyrat-backdoor-adware/121175/

import "hash"

rule IOC_ValleyRAT_masquerading_as_adware_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: ValleyRAT masquerading as adware. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/valleyrat-backdoor-adware/121175/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "c24e99f9437feacaa63766a3cde3fe3d" or
        hash.md5(0, filesize) == "7ad1e3ef4e6d9d636c9e7e967733850e" or
        hash.md5(0, filesize) == "96b4c1d0683dce22bd3223e1e40689c1" or
        hash.md5(0, filesize) == "9b86d3ab6cef15c633933fbbeab39c0a" or
        hash.md5(0, filesize) == "edfdc30cbd85879776b8f735ea7de1f1" or
        hash.md5(0, filesize) == "07ddbbe2c71c45577a7a4fbcdba0df91" or
        hash.md5(0, filesize) == "48826d5ca845979d2e6ebd66dc1aae90" or
        hash.md5(0, filesize) == "6c158c0f8e029342192d4f0d72e102b7" or
        hash.md5(0, filesize) == "9a71d6a41cd258b9e89cdc5fc224de73" or
        hash.md5(0, filesize) == "8a626d844943da3456b044f38deae3a2"
}

