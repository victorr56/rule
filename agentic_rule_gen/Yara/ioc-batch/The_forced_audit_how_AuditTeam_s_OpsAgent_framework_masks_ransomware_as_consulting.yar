// The forced audit: how AuditTeam’s OpsAgent framework masks ransomware as consulting
// Source: securelist | https://securelist.com/auditteam-opsagent-forced-audit/122031/

import "hash"

rule IOC_The_forced_audit_how_AuditTeam_s_OpsAgent_framework_masks_ransomware_as_consulting_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The forced audit: how AuditTeam’s OpsAgent framework masks ransomware as consulting. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/auditteam-opsagent-forced-audit/122031/"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "f4bb8c7e15d8b98d535eb20b09176b3d" or
        hash.md5(0, filesize) == "d3e49dceb89a25f5da4ff0c42e996857" or
        hash.md5(0, filesize) == "bd4c327ad208cb722ad25e43ea3f35fc" or
        hash.md5(0, filesize) == "5d1425ab3dad1d2de053f69529d227e1" or
        hash.md5(0, filesize) == "f0d5752054f6b7af1325ea340c4326d0" or
        hash.md5(0, filesize) == "83768e994c6bb72d0b430b98a71ec8d6" or
        hash.md5(0, filesize) == "109cdc24ccd4872a3e4bf6f2d4f3c3d4"
}

