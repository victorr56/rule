// Vwork: Weaponized Open-source Software as an Addon for Gigabud
// Source: group-ib | https://www.group-ib.com/blog/vwork-app-cloning-gigabud-goldfactory/

import "hash"

rule IOC_Vwork_Weaponized_Open_source_Software_as_an_Addon_for_Gigabud_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Vwork: Weaponized Open-source Software as an Addon for Gigabud. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/vwork-app-cloning-gigabud-goldfactory/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "b769721621aed0418b193e4a00e51bc772c8383a4149d23a5425b13475e2d501" or
        hash.sha256(0, filesize) == "ae6f6eeba2bd4cc948d24610d9447986e52f913f4b5ff960ddea26075ff621ae" or
        hash.sha256(0, filesize) == "4fff28eecc0ab6303e4948df77671009dda5b93ed3d1cead527b02d1317426bc" or
        hash.sha256(0, filesize) == "112fefc9348fa4acbb82d54d9688c96dd5671bcb2e6288c1f7f384baa8d2fdcf" or
        hash.sha256(0, filesize) == "9ca27df7938f12794bab0847434482955ca9adea714a34afd315c7a7be522611" or
        hash.sha256(0, filesize) == "66499653c0fff78d81db5dc319b9aaa0288dc5d76f555a5eba73660c0ee810eb" or
        hash.sha256(0, filesize) == "61274cf9f49e04e559b267d18617d352c48ba3b1f453773ee9f30e5a4e25dbbc"
}

