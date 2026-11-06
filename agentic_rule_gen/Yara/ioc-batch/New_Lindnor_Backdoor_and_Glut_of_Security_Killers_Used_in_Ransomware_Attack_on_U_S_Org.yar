// New Lindnor Backdoor and Glut of Security Killers Used in Ransomware Attack on U.S. Org
// Source: symantec-threat-hunter | https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware

import "hash"

rule IOC_New_Lindnor_Backdoor_and_Glut_of_Security_Killers_Used_in_Ransomware_Attack_on_U_S_Org_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: New Lindnor Backdoor and Glut of Security Killers Used in Ransomware Attack on U.S. Org. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "symantec-threat-hunter"
        reference   = "https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware"
        date        = "2026-11-06"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "fc200686175559f4544a5de826905f09a68476d889690a3be40ac32356790cb8" or
        hash.sha256(0, filesize) == "5d2dd9caf2ae4a5083dbec16e688040456cdbc31eaeecbab78188e322ed0415b" or
        hash.sha256(0, filesize) == "ad9575a9ef2dcc9d2fd2a24376c418549d4b3db5564c22b20081d33cf7629e43"
}

