// Dark Pink
// Source: group-ib | https://www.group-ib.com/blog/dark-pink-apt/

import "hash"

rule IOC_Dark_Pink_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Dark Pink. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/dark-pink-apt/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "9976625b5a3035dc68e878ad5ac3682ccb74ef2007c501c8023291548e11301a" or
        hash.sha256(0, filesize) == "c60f778641942b7b0c00f3214211b137b683e8296abb1905d2557bfb245bf775" or
        hash.sha256(0, filesize) == "e3181ee97d3ffd31c22c2c303c6e75d0196912083d0c21536e5833ee7d108736" or
        hash.sha256(0, filesize) == "e45df7418ca47a9a4c4803697f4b28c618469c6e5a5678213ab81df9fcc9fd51" or
        hash.md5(0, filesize) == "926027f0308481610c85f4e3e433573b" or
        hash.md5(0, filesize) == "728afa40b20df6d2540648ef845eb754" or
        hash.md5(0, filesize) == "7eaf1b65004421ac07c6bb1a997487b2" or
        hash.md5(0, filesize) == "732091ad428419247bce87603ea79f00" or
        hash.sha1(0, filesize) == "24f65e0ee158fc63d98352f9828d014ab239ae16" or
        hash.sha1(0, filesize) == "d8df672ecd9018f3f2d23e5c966535c30a54b71d" or
        hash.sha1(0, filesize) == "18ca159183c98f52df45d3e9db0087e17596a866" or
        hash.sha1(0, filesize) == "142f909c26bd57969ef93d7942587cdf15910e34"
}

