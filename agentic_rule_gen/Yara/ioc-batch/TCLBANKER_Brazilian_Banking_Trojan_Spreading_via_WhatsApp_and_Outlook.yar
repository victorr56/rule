// TCLBANKER: Brazilian Banking Trojan Spreading via WhatsApp and Outlook
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/tclbanker-brazilian-banking-trojan

import "hash"

rule IOC_TCLBANKER_Brazilian_Banking_Trojan_Spreading_via_WhatsApp_and_Outlook_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: TCLBANKER: Brazilian Banking Trojan Spreading via WhatsApp and Outlook. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/tclbanker-brazilian-banking-trojan"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626" or
        hash.sha256(0, filesize) == "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059" or
        hash.sha256(0, filesize) == "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40" or
        hash.sha256(0, filesize) == "63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394" or
        hash.sha1(0, filesize) == "91fafaa1240676afe5c55d931261e3798797c408"
}

