// Catching Ransomware: Introducing encrypts-files and Stricter MITRE ATT&CK T1486
// Source: virustotal | https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html

import "hash"

rule IOC_Catching_Ransomware_Introducing_encrypts_files_and_Stricter_MITRE_ATT_CK_T1486_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Catching Ransomware: Introducing encrypts-files and Stricter MITRE ATT&CK T1486. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "virustotal"
        reference   = "https://blog.virustotal.com/2026/11/catching-ransomware-introducing.html"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "d243031985f7fa82a741e5677a227c65b2e2f1b07e0e10f00fe575dcc0eb4645" or
        hash.sha256(0, filesize) == "98110dedcca5803bc211f2d8dd640de79a2ba2a69d1def2f4970fa7799313f3e" or
        hash.sha256(0, filesize) == "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18" or
        hash.sha256(0, filesize) == "94b93a47e3e9e47e6daf5beee9007e90f9aaffb67598c3d18605620b284be08f"
}

