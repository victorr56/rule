// Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack
// Source: huntress | https://www.huntress.com/blog/mapping-akira-ransomware-attack

import "hash"

rule IOC_Up_a_Creek_Without_a_Command_Line_Mapping_an_Akira_Ransomware_Attack_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/mapping-akira-ransomware-attack"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "1f1bb322591b6d27fd2946e373d7d2efc2f4e1e66818846060d391600b600fba" or
        hash.sha256(0, filesize) == "d00833318a04caa019c6f95dcb3598ad947d405010bfb2f3cbd04530a00bc3a4"
}

