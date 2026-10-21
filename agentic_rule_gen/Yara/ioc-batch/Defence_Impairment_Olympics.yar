// Defence Impairment Olympics
// Source: huntress | https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment

import "hash"

rule IOC_Defence_Impairment_Olympics_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Defence Impairment Olympics. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/mimikatz-credential-dumping-defence-impairment"
        date        = "2026-10-17"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "bd74a00f4d2ec3bf50d13ddf324bb368b2464d547abd0c572ef5e2f77943a920" or
        hash.sha256(0, filesize) == "40859ede262098086962ab00c89f02452aa9941c88c7f4ac002db166179980c6" or
        hash.sha256(0, filesize) == "f63d293e117cae1d0a6c24359fc1361a9dc48178049cc6491051b09268c8c39c" or
        hash.sha256(0, filesize) == "94cd18f3f030fcc9b259dc410b17ea72a1f9800ee654f8e0f07a87bb9443b593" or
        hash.sha256(0, filesize) == "793768ce4fadab044c7502ea5ec4d8e1569283f289dfd73419e119f32d56d0f3" or
        hash.sha256(0, filesize) == "f0ff36ecdc843351913dbfbd9122b62563894936ff64215a7a2f89181ebdb57f"
}

