// DarkMe RAT: A VB6 APT Trojan Turned Conventional Infostealer
// Source: huntress | https://www.huntress.com/blog/darkme-rat-abandons-exploits

import "hash"

rule IOC_DarkMe_RAT_A_VB6_APT_Trojan_Turned_Conventional_Infostealer_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: DarkMe RAT: A VB6 APT Trojan Turned Conventional Infostealer. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "huntress"
        reference   = "https://www.huntress.com/blog/darkme-rat-abandons-exploits"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "54ed18aa883b53794810be0428b3a0167758183c5b3ba5660af747dc81dd5b76" or
        hash.sha256(0, filesize) == "394c93dfbb7581c66a23c52b20cd90b31415c0825a2eab7107e60ee3fe693c04" or
        hash.sha256(0, filesize) == "9fb5888f9ac99227a35f3e08ca08bfb9eed676e1f91638599eba0d7a5aac847f" or
        hash.sha256(0, filesize) == "1c923c685f97e556f241d0f1880283500a61dc7ecae8cafe75f34c720ff6b918" or
        hash.sha256(0, filesize) == "52b242047a8055c0936b384b952c1c16c1072a590610140b01f4acefa8ae883a" or
        hash.sha256(0, filesize) == "4a18f65ab7de7be385cbcebc78c9ae49334294f93726822b8900f9b7a324a6b0" or
        hash.sha256(0, filesize) == "3052352ac811c48590f0239281312c35560fc06b4dc39790e365eb1e7cab8634" or
        hash.sha256(0, filesize) == "d7185bd7b450b478c793ece3025bdd867eed70bb7b739a5f26375b5ba6cf0d93" or
        hash.sha256(0, filesize) == "2915efecf2a01ce0b3ef49c47666ec43c326e7804df10e5859db5f08eeca8a37"
}

