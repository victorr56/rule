// Masters of disguise
// Source: group-ib | https://www.group-ib.com/blog/bootkits/

import "hash"

rule IOC_Masters_of_disguise_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Masters of disguise. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/bootkits/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "f5b320f7e87cc6f9d02e28350bb87de6" or
        hash.md5(0, filesize) == "dd8d3718197a10097cd72a94ed223238" or
        hash.md5(0, filesize) == "91a473d3711c28c3c563284dfafe926b" or
        hash.md5(0, filesize) == "0c136186858fd36080a7066657de81f5" or
        hash.md5(0, filesize) == "9f13636d5861066835ed5a79819aac28" or
        hash.md5(0, filesize) == "fa0a874926453e452e3b6ced045d2206" or
        hash.md5(0, filesize) == "72c514c0b96e3a31f6f1a85d8f28403c" or
        hash.md5(0, filesize) == "0d386ebba1ccf1758a19fb0b25451afe" or
        hash.md5(0, filesize) == "b53880397d331c6fe3493a9ef81cd76e" or
        hash.md5(0, filesize) == "7b213a6ce7ab30a62e84d81d455b4dea" or
        hash.md5(0, filesize) == "a69205984849744c39cfb421d8e97b1f" or
        hash.md5(0, filesize) == "08ecd8068617c86d7e3a3e810b106dce" or
        hash.md5(0, filesize) == "89527f932188bd73572e2974f4344d46" or
        hash.md5(0, filesize) == "afc09deb7b205eadae4268f954444984" or
        hash.md5(0, filesize) == "6e949601ebdd5d50707c0af7d3f3c7a5" or
        hash.md5(0, filesize) == "92f6c00da977110200b5a3359f5e1462" or
        hash.md5(0, filesize) == "d197648a3fb0d8ff6318db922552e49e" or
        hash.md5(0, filesize) == "74db88b890054259d2f16ff22c79144d" or
        hash.md5(0, filesize) == "449be89f939f5f909734c0e74a0b9751" or
        hash.md5(0, filesize) == "67cf741e627986e97293a8f38de492a7" or
        hash.md5(0, filesize) == "cfb072d1b50425ff162f02846ed263f9"
}

