// The invisible passenger in your car
// Source: securelist | https://securelist.com/android-head-unit-malware/121106/

import "hash"

rule IOC_The_invisible_passenger_in_your_car_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The invisible passenger in your car. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/android-head-unit-malware/121106/"
        date        = "2026-10-16"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.md5(0, filesize) == "3ad4bf5a86d26ffbf09cae42af330a98" or
        hash.md5(0, filesize) == "ba27951b4ee1c341f4415d033369ecd3" or
        hash.md5(0, filesize) == "d63bacd6d6709dd68a10ef9d374c7835" or
        hash.md5(0, filesize) == "6c2e34b30da42085240ede53ab6107d4" or
        hash.md5(0, filesize) == "8b5e513144a6138a966ea59e68bf9da2" or
        hash.md5(0, filesize) == "e119845877089d6f4b0a70dc7388f316" or
        hash.md5(0, filesize) == "e9f3a0dab6949ce2cddab9e0aa80ae1a" or
        hash.md5(0, filesize) == "0fbaa7092204f4b1494e0b840b014774" or
        hash.md5(0, filesize) == "1dcf031c40ce456b6a36a00b0acf3d11" or
        hash.md5(0, filesize) == "44b6b213a6a3f299eaf88e078de95ecb" or
        hash.md5(0, filesize) == "67dc78e544ebce16b85dc7c195dfbc58" or
        hash.md5(0, filesize) == "9642ae619b3165d23c6349002d1abe24" or
        hash.md5(0, filesize) == "b067d5b0dbecbd6498bcdfba45dba77e" or
        hash.md5(0, filesize) == "f0e3f7eba2cde91e2dedb921bab47422" or
        hash.md5(0, filesize) == "412e9243f2981bbea3894254d105b3b8" or
        hash.md5(0, filesize) == "71ab5517f71866279d0d87d37f2ae320" or
        hash.md5(0, filesize) == "bd80bd3c3d0e4bf6b5b4a825650d01f5" or
        hash.md5(0, filesize) == "fe71af9ecf174de48d2b2ccc2c15fb04" or
        hash.md5(0, filesize) == "fa831c3c23824b99871163387bcda7ad" or
        hash.md5(0, filesize) == "2a64c3efc11bf224aa54f24e876446c9" or
        hash.md5(0, filesize) == "7a4d3ba2dacccfdda55859a5dfee2671" or
        hash.md5(0, filesize) == "ea24487996eb70c1780922fb3063bcc5"
}

