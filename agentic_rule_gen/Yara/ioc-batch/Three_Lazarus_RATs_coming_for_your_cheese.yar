// Three Lazarus RATs coming for your cheese
// Source: fox-it | https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/

import "hash"

rule IOC_Three_Lazarus_RATs_coming_for_your_cheese_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Three Lazarus RATs coming for your cheese. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "fox-it"
        reference   = "https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "774c71664d5d25775478607e74555462773e525e18237947355228337f433a3b" or
        hash.sha256(0, filesize) == "24d5dd3006c63d0f46fb33cbc1f576325d4e7e03e3201ff4a3c1ffa604f1b74a" or
        hash.sha256(0, filesize) == "4715e5522fc91a423a5fcad397b571c5654dc0c4202459fdca06841eba1ae9b3" or
        hash.sha256(0, filesize) == "8c3c8f24dc0c1d165f14e5a622a1817af4336904a3aabeedee3095098192d91f" or
        hash.sha256(0, filesize) == "9dddf5a1d32e3ba7cc27f1006a843bfd4bc34fa8a149bcc522f27bda8e95db14" or
        hash.sha256(0, filesize) == "2c164237de4d5904a66c71843529e37cea5418cdcbc993278329806d97a336a5" or
        hash.md5(0, filesize) == "435c7b4fd5e1eaafcb5826a7e7c16a83" or
        hash.md5(0, filesize) == "6f2f61783a4a59449db4ba37211fa331"
}

