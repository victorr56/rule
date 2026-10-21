// Lost in relocation: analysis of a new loader distributing CASTLESTEALER
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/oxloader-malware-loader-infostealer

import "hash"

rule IOC_Lost_in_relocation_analysis_of_a_new_loader_distributing_CASTLESTEALER_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Lost in relocation: analysis of a new loader distributing CASTLESTEALER. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/oxloader-malware-loader-infostealer"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "fdfc7831e5c24cfa80152860dfe8c056ba079f7df1393bf6bb7b18ed974eda37" or
        hash.sha256(0, filesize) == "de4f51649ec1a33071854aefe93ffb3fc225e19f802d8dd914676dd5dfef2615" or
        hash.sha256(0, filesize) == "9a9939dff297997732aaade9b243d695632cbd64033c5fbcb9de3d09b7e6c28d" or
        hash.sha256(0, filesize) == "c85f2765a6c3c3f3907c17e57df12f8f68826f74bff3bbfd272af50666d065fe" or
        hash.sha256(0, filesize) == "4ec9d9d4d10ad78fc6d7bda7cb17d52984878ccd2dd4302fd1cef152313b9741" or
        hash.sha256(0, filesize) == "39019279686c820c3af5684012a0085a7e2109f612c9fab886dd0577ace5b5c6" or
        hash.md5(0, filesize) == "6e0a1f8f77f7011561f6f9ca96b71b8f" or
        hash.md5(0, filesize) == "956c6128e9362e075f8d006c93616a66"
}

