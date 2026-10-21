// skynox7: Proxyjacking Edge Devices Into Residential Proxies
// Source: greynoise | https://www.greynoise.io/blog/proxyjacking-edge-devices-residential-proxies

import "hash"

rule IOC_skynox7_Proxyjacking_Edge_Devices_Into_Residential_Proxies_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: skynox7: Proxyjacking Edge Devices Into Residential Proxies. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "greynoise"
        reference   = "https://www.greynoise.io/blog/proxyjacking-edge-devices-residential-proxies"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "e3dedf983c572d3e646a9b70fe9b41be497a3a2e5342c36dd3bd37cef7ebeffd" or
        hash.sha256(0, filesize) == "fdc18f4287c1c6a285c664d3ce0f17d3479bc246bc6c163eb90b1a84adb453a7" or
        hash.sha256(0, filesize) == "4fd7fa22776dbfde7ddaf02a4f904564593e2ed69f87cbb7bbd6c206a874ecf7" or
        hash.sha256(0, filesize) == "26abd52f207739556282023e82873424795abc5e527771205a40749f90c01f6e" or
        hash.sha256(0, filesize) == "df27938d26c1c9421ff307aafcb87131521e05f5d87ecaaab4a32ece3335fee4" or
        hash.sha256(0, filesize) == "2c12a3193b1528cd0a88d4fcfa0c060404de4c2bbe1fecb3fc3fa347f04e0165" or
        hash.sha256(0, filesize) == "71f2924a549a8f79a48ff332b071a12cd0b01e9ba643e9f8ed7b72b6d382325d"
}

