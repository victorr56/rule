// Old Gremlins, new methods
// Source: group-ib | https://www.group-ib.com/blog/oldgremlin-comeback/

import "hash"

rule IOC_Old_Gremlins_new_methods_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Old Gremlins, new methods. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/oldgremlin-comeback/"
        date        = "2026-10-23"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "700fc6c697a869cc978d042b024e59c5fcd4e8905c2fbc7caeeb3760c2905b5c" or
        hash.sha256(0, filesize) == "ea95c527da29ca29072617dce28a567d11a7c777f2fcc2a752d0dff626180e70" or
        hash.sha256(0, filesize) == "4682a66efa7c79ab56dfdfc1bba5cf001d380d516ff1b64acea0b53784fde8cc" or
        hash.sha256(0, filesize) == "476852e3257631d6ac2882237cfa146dcaefe17a10a11b984aec5cc9b61d48d4" or
        hash.sha256(0, filesize) == "09c0ac9e09f91a415f674c6cd27b1cc44d8c695da6a449d6baf70107027af2fa" or
        hash.sha256(0, filesize) == "f1102cceed4e6529f8c5b1bf387b798bfba727b49c4a7442b19c392335291cab" or
        hash.sha256(0, filesize) == "bc7ccad7d1ed91a45e792866ff9a060414c1d3c2f9ae8f06689cb96a2e3957a6" or
        hash.sha256(0, filesize) == "f36305e01515b73607f0f8941d9093fabe1b7a7e3f90c18f137403a0f016cdff" or
        hash.sha256(0, filesize) == "0a0889330501ee52ca5fe2b2f41fbcad7d26afce8bc430c7fe274e6ebe64c680" or
        hash.sha256(0, filesize) == "4ff26fed848df58550c656fb1676a9afded48060381c55d45154a90a3272ba9e" or
        hash.sha256(0, filesize) == "990ef464d76b206e4727ee9ccba9c0be33a278a26116c3c2c839125abc97777f" or
        hash.sha256(0, filesize) == "8f3747775a1bdeae4627763687bdcb2ef325874e7a908f3ec24380c5d2f2b44a" or
        hash.sha256(0, filesize) == "2b507a5d9af760667e18cd11584816575d102d7e9e1900de29b8513d30f6d65c" or
        hash.md5(0, filesize) == "70f4416f6ec6c0dbf916a717bc4a612f" or
        hash.md5(0, filesize) == "669cd24d66587ebdbb709302ed011c0e" or
        hash.md5(0, filesize) == "b59b53c35f03cff659f848297bcf3314" or
        hash.md5(0, filesize) == "fc763a77dffdbbc62d256524cd4808d9" or
        hash.md5(0, filesize) == "3e4ab86263e0ff5a35f2e3fb17d03727" or
        hash.md5(0, filesize) == "64db43f22430e75716aacd7ca13bbac6" or
        hash.md5(0, filesize) == "0c46a727d2b9d6e0d1c3bee3b9e90abf" or
        hash.md5(0, filesize) == "858d14841bc1cc90e8e24a51aca814e1" or
        hash.md5(0, filesize) == "e8fce013184401fb8d6e248fc91b4f9e" or
        hash.md5(0, filesize) == "e959fa8191ca2e4dd99932e149668ade" or
        hash.md5(0, filesize) == "0ead98011c8d777fd2772d41ab990111" or
        hash.md5(0, filesize) == "9dc7f56d0bb5d7543d0ea4a644110623" or
        hash.md5(0, filesize) == "1ddda12e2a8594bc458dbf22b4b39c27" or
        hash.sha1(0, filesize) == "dda9900cefa8cdc8ec362d80480ba6c4cfdc62b2" or
        hash.sha1(0, filesize) == "c82e12e563d5d5f4a8dd67703b5df7373b457abc" or
        hash.sha1(0, filesize) == "bd0a6a3628f268a37ac9d708d03f57feef5ed55e" or
        hash.sha1(0, filesize) == "af3190de95dd187661d0866404b087ec7bb8c6ba" or
        hash.sha1(0, filesize) == "313c8241e0c74fac52530c55089979ac4763e0e2" or
        hash.sha1(0, filesize) == "fab504d579b2e1aae8701ea1bda3f3a8b694927f" or
        hash.sha1(0, filesize) == "e1b5fc5df05b25fc7136cf9b7ea252e50ebff2ef" or
        hash.sha1(0, filesize) == "3c1b1942537ee273325b02ec305bb02e2d0a02f8" or
        hash.sha1(0, filesize) == "79526eaf1489762ca1deca358d6742f9c1718ca6" or
        hash.sha1(0, filesize) == "9569f635576ec5460571ca6ee02f9b01f39956ea" or
        hash.sha1(0, filesize) == "dbaad9f3af3e48da6ef6a93747b2a1939ffa4b3d"
}

