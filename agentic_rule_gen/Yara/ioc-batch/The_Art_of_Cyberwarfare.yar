// The Art of Cyberwarfare
// Source: group-ib | https://www.group-ib.com/blog/task/

import "hash"

rule IOC_The_Art_of_Cyberwarfare_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The Art of Cyberwarfare. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/task/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "7874c9ab2828bc3bf920e8cdee027e745ff059237c61b7276bbba5311147ebb6" or
        hash.sha256(0, filesize) == "849e6ed87188de6dc9f2ef37e7c446806057677c6e05a367abbd649784abdf77" or
        hash.sha256(0, filesize) == "95ac5cc14f114461df8469331171863e8d8c1981761cf16c68d513e34a46103d" or
        hash.sha256(0, filesize) == "1457ce3a4f2f4b41a345cf06abd7c7af0d14a3ceaf61e3ff863a787cee43b48a" or
        hash.sha256(0, filesize) == "2629cae63cecc23bd30731e3a7e44fdabee75a1aaec14b3d7f56ac1674ad9c11" or
        hash.sha256(0, filesize) == "fd43fa2e70bcc3b602363667560494229287bf4716638477889ae3f816efc705" or
        hash.sha256(0, filesize) == "83b619f65d49afbb76c849c3f5315dbcb4d2c7f4ddf89ac93c26977e85105f32" or
        hash.sha256(0, filesize) == "2a3c8dabdee7393094d72ce26ccbce34bff924a1be801f745d184a33119eeda4" or
        hash.sha256(0, filesize) == "71750c58eee35107db1a8e4d583f3b1a918dbffbd42a6c870b100a98fd0342e0" or
        hash.sha256(0, filesize) == "690bf6b83cecbf0ac5c5f4939a9283f194b1a8815a62531a000f3020fee2ec42" or
        hash.md5(0, filesize) == "664fb7cda349da4d36afa7a15f7f14f5" or
        hash.md5(0, filesize) == "5155c03a2064d80cef6a86a84d67c1b4" or
        hash.md5(0, filesize) == "aa9771e98f25db395c7d9f5beb9e5421" or
        hash.md5(0, filesize) == "ceb80ceffc82f10acdbe9841e4588eb2" or
        hash.md5(0, filesize) == "101b7762ef536cf77f04e07115231b53" or
        hash.md5(0, filesize) == "f481172e59491117ac5dbe2ade267b1f" or
        hash.md5(0, filesize) == "fb82e5a2f9f25ac53f3f4c8b8e33ffdd" or
        hash.md5(0, filesize) == "9fb74044c1935298a7c00b74fa192baf" or
        hash.md5(0, filesize) == "32060465223315a1da24c0fb4a6e51f5" or
        hash.md5(0, filesize) == "4814f81f3b174c52e920e6ddd57d8da6" or
        hash.md5(0, filesize) == "43021febc8494d66a8bc60d0fa953473" or
        hash.md5(0, filesize) == "68320a454321f215a3b6fcd7d585626b" or
        hash.md5(0, filesize) == "7210d5941678578c0a31adb5c361254d" or
        hash.md5(0, filesize) == "41e9907a6c468b4118e968a01461a45b" or
        hash.sha1(0, filesize) == "c9e03855f738e360d24018e2d203142c7ae6c2ec" or
        hash.sha1(0, filesize) == "6857bb2c3ae5f9c2393d9f88816be7a10cb5573f" or
        hash.sha1(0, filesize) == "bc708acdf6b8b60577268a0788f1e375cb3ffeb4" or
        hash.sha1(0, filesize) == "08645d079abe05b88201db0ff1c9b1ec035035ca" or
        hash.sha1(0, filesize) == "ae57d779aac235e979fae617599377a099b148ab" or
        hash.sha1(0, filesize) == "3ff73686244ca128103e86d8c5aa024e37e7b86d" or
        hash.sha1(0, filesize) == "a55260aa75e7f28ad6644f916fe11c6bd2a93ba2" or
        hash.sha1(0, filesize) == "aa046d7b6d37070ea7a65d13ddf0f3bd8668a723" or
        hash.sha1(0, filesize) == "c89896264a633fd7a036042d3202c6b9503d11cb" or
        hash.sha1(0, filesize) == "bfa38cb5097bba6a8ae555d6dce3c5446db8099a"
}

