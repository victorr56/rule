// Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory GPO
// Source: securelist | https://securelist.com/tr/payload-ransomware-via-group-policy/121335/

import "hash"

rule IOC_Group_Policy_hijacked_PAYLOAD_ransomware_weaponizes_Active_Directory_GPO_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory GPO. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/tr/payload-ransomware-via-group-policy/121335/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "0108656a3e1ade6ca4f21b084f5e1208" or
        hash.md5(0, filesize) == "bea5e267f24d7da59f6821bffdbff293"
}

