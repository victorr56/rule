// Unmasking Phishing: Strategies for identifying 0ktapus domains and beyond
// Source: wiz | https://www.wiz.io/blog/unmasking-phishing-strategies-for-identifying-0ktapus-domains

import "hash"

rule IOC_Unmasking_Phishing_Strategies_for_identifying_0ktapus_domains_and_beyond_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Unmasking Phishing: Strategies for identifying 0ktapus domains and beyond. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "wiz"
        reference   = "https://www.wiz.io/blog/unmasking-phishing-strategies-for-identifying-0ktapus-domains"
        date        = "2026-10-25"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "fb1d07ab6c54c7380a93a507b48bc5ba0aee77ca32b7d4c57c38f007857a6fd1" or
        hash.sha256(0, filesize) == "95a0eca17ee49bebb333bbb1c96ab54ed361c2f233b2adf8c4374814c633a53b" or
        hash.sha256(0, filesize) == "69b575025bd763e58fcb95035b9b6e358f43737d91e01ebdaa19934e0206a966" or
        hash.sha256(0, filesize) == "98ca25eef00efcafee4f9cb07908776d0ad976296a5e6eb07a724c31ae4bfc61" or
        hash.sha256(0, filesize) == "dd4782fc37ada8c2411fd65877eb3c3199aa67224ffa6c65b81c2e4b8658f727" or
        hash.sha256(0, filesize) == "f8b7bb31e7e8c574d74e52eba7dcf3de48c7f5fa6d39d64685d39355d688defb" or
        hash.sha256(0, filesize) == "5dd491b89daadabfe8419d5d1e436a6dd9b4eea25fc4ba5898e6a1bca34f06e9" or
        hash.sha256(0, filesize) == "46e7cf1fb46a73f098fa6f0f46732bdd298af690ec1452fac9b97884ca8b5a39"
}

