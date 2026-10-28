// From Hijacked PBX to Stolen Trunk: INJ3CTOR3’s Campaign Evolves
// Source: cyble | https://cyble.com/blog/hijacked-pbx-to-stolen-trunk-inj3ctor3s-campaign/

import "hash"

rule IOC_From_Hijacked_PBX_to_Stolen_Trunk_INJ3CTOR3_s_Campaign_Evolves_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From Hijacked PBX to Stolen Trunk: INJ3CTOR3’s Campaign Evolves. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "cyble"
        reference   = "https://cyble.com/blog/hijacked-pbx-to-stolen-trunk-inj3ctor3s-campaign/"
        date        = "2026-10-28"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "c6e64453ea8bc0856333b6f57567c9efd8c440410787cae135d1c4a248c07c0d" or
        hash.sha256(0, filesize) == "38edbfc4ac89619d2bdb3f4bb2626deaaf422868d6d7af640f59d7959903f838" or
        hash.sha256(0, filesize) == "1c14a761620691a43b1a554a9eccd38d21c15d59463945250d4f57b10d20fce9" or
        hash.sha256(0, filesize) == "b54a8d9e98ff36dfe63b2aea97a2003b670f7311595bb4dd072850fed5900a0b" or
        hash.sha256(0, filesize) == "aa6dfd7ee90d9aea5af29ae39c14ff70cf8687118abadd7aa4fc98923f01ffd1" or
        hash.sha256(0, filesize) == "adeb015fdb37814edc3ed45230f48d2b0e87bb195a5a7e4487c01549b47c744c" or
        hash.sha256(0, filesize) == "d345671e688ee807e1bb9b6fc45e6bb0611bbb1331c33888c8030ec2db47e672" or
        hash.md5(0, filesize) == "a2f6863413c4192a4abfa360577b9961" or
        hash.md5(0, filesize) == "8b3a1d970fda0c17a0b785a990fb7b6a" or
        hash.md5(0, filesize) == "bd42a8a0d23ae16c85dede7d2abaec05" or
        hash.md5(0, filesize) == "7544725ebaaadac217dfaa7ca8e8fe7e"
}

