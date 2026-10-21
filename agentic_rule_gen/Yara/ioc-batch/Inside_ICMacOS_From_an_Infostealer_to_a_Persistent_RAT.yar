// Inside ICMacOS: From an Infostealer to a Persistent RAT
// Source: socradar | https://socradar.io/blog/icmacos-infostealer-rat/

import "hash"

rule IOC_Inside_ICMacOS_From_an_Infostealer_to_a_Persistent_RAT_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Inside ICMacOS: From an Infostealer to a Persistent RAT. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "socradar"
        reference   = "https://socradar.io/blog/icmacos-infostealer-rat/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "5dfb0c01ac5c075e23ec37873b30ba16cf28e290e9439d04101f0a8191f929d8" or
        hash.sha256(0, filesize) == "8cc449e7e240894e77187f6faff415bc8b9f2f9da73f60eef1f7605debd9144a" or
        hash.sha256(0, filesize) == "62e435102e1e1de74537f174ede7c8ff198dc4df3fd2e1167f537096e0b4dd17" or
        hash.sha256(0, filesize) == "857236d1902f4604acdf27519c0310064d21f8a82af3b95b1e4f02fef581b1d0" or
        hash.sha256(0, filesize) == "6917505bbdc8efa01ea1a0298eae62a93a57a8c98d3712a69d822dca4a667f05" or
        hash.sha256(0, filesize) == "dca852b53c259641e1782bd9122c5007130614a7a8fd17102400acb4f50f6e94" or
        hash.sha256(0, filesize) == "e7e8ac14aaee970c6d00c6cbb398decc56dfc128974c01bfc8e7acd13a18576e" or
        hash.sha256(0, filesize) == "ec37acd3bd15f50eee2941d5644ca0ee738b36ce4a39e9e08058e35ebc7961fc" or
        hash.sha256(0, filesize) == "fcf9de13ecc70b4fda3998ed7a93849edf86c48767a1a13f32f4a6a631a65ae2" or
        hash.sha256(0, filesize) == "3d4f70172c8f31813e7b37fc1a49bce193663e33c4eb65952bb5aec9d7176826" or
        hash.sha256(0, filesize) == "8b7606bdccdd6ff691db875283fdf5b6b658dd8d4d141b44e07f8f2583ff5604" or
        hash.sha256(0, filesize) == "bc8d70f000e73c0c7a69a2676805190e7109cab59df3e34c5a74d2cb7f13a7e4" or
        hash.sha256(0, filesize) == "a9b21ac0112855b835b5e5850ef167471eff7305d42b3a8104c1961b257a444d" or
        hash.sha256(0, filesize) == "c8136413ad38a1028050f5d508e25267b518c5fdeac80b6442103d1009d8924c" or
        hash.sha256(0, filesize) == "e52855d447d152bb698e565f361161cdc8946183ab09bf3cbea89765a2b5ff31" or
        hash.sha256(0, filesize) == "d9df05a3fb68d302ecf134a1214b609c6ec0a3fb9122907214afac3908b587f4" or
        hash.sha256(0, filesize) == "8b4303a065e18e80050ef22031ec60b1a4e84f958d9e56cc5cc34cd29d988d69"
}

