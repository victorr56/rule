// Rapid7 Analysis: NetScaler intrusions chaining CVE-2026-88771 and CVE-2026-88779
// Source: rapid7 | https://www.rapid7.com/blog/post/ra-netscaler-intrusions-chaining-cve-2026-88771-and-cve-2026-88779

import "hash"

rule IOC_Rapid7_Analysis_NetScaler_intrusions_chaining_CVE_2026_88771_and_CVE_2026_88779_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Rapid7 Analysis: NetScaler intrusions chaining CVE-2026-88771 and CVE-2026-88779. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "rapid7"
        reference   = "https://www.rapid7.com/blog/post/ra-netscaler-intrusions-chaining-cve-2026-88771-and-cve-2026-88779"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "a0ba4e1ad622d9c3d950b4156d4430812d05bee216ab22c3804a9f7a80535556" or
        hash.sha256(0, filesize) == "6774bfed99da38cec82e721de4bd64a67db7840efadcc71e7df02eb6f0a03c44" or
        hash.sha256(0, filesize) == "56a892d80096a9db4ca473a9c3109729c60a5ba901d6ba65948bdb1f4a6fb186" or
        hash.sha256(0, filesize) == "8e8b9532ce40eacfe1b4cf2b11241878b70b910aabd90b453b1460df19b51a4d" or
        hash.sha256(0, filesize) == "eaf0086237879bbaac00a5874c0e2ff84deede1ba10e6b706e2288fd3a31cdde" or
        hash.sha256(0, filesize) == "ffe052fc50271e7739d458b155df790438776032bfd125b974735e1dd9c0b138"
}

