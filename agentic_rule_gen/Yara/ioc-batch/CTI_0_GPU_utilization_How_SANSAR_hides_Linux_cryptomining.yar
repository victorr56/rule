// 0% GPU utilization: How SANSAR hides Linux cryptomining
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware

import "hash"

rule IOC_CTI_0_GPU_utilization_How_SANSAR_hides_Linux_cryptomining_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: 0% GPU utilization: How SANSAR hides Linux cryptomining. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        date        = "2026-11-20"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e" or
        hash.sha256(0, filesize) == "96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46" or
        hash.sha256(0, filesize) == "acc706afc9322a3eae1ef49049749e0a7c9f1a123895ac56dc8a289beb2fb5b7" or
        hash.sha256(0, filesize) == "cc1ad7f14777a098ccc91fd4e8f6143da14418c2b6fdf23b7f8f6b3d1b0b7f1d" or
        hash.sha256(0, filesize) == "675c24728f87f7aa0fa07527027c95c24c246049c65eaef89270ab04ea50a180" or
        hash.sha256(0, filesize) == "6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4" or
        hash.sha256(0, filesize) == "df8ab6fd699e6ae90e63e9696bae8f01342708bafc2ed88af414337e4f237194"
}

