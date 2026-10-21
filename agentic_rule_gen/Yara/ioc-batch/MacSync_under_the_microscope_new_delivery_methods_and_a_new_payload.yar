// MacSync under the microscope: new delivery methods and a new payload
// Source: securelist | https://securelist.com/macsync-new-version/121383/

import "hash"

rule IOC_MacSync_under_the_microscope_new_delivery_methods_and_a_new_payload_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: MacSync under the microscope: new delivery methods and a new payload. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "securelist"
        reference   = "https://securelist.com/macsync-new-version/121383/"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "cb09ff86cabde4f8cee2d3cdec370c623bfa6c2b72ae9750fc9a7b299c65d7ca" or
        hash.sha256(0, filesize) == "3744f975113dfc552df982dcae699f9154a448e05a743bdfb641a463352bc13a" or
        hash.sha256(0, filesize) == "ff664112d3215c5d184689fc836e0dc6c1a47e42c34e70b2c3d356864bc4cb4c" or
        hash.md5(0, filesize) == "3a1af2b397c6958e6c3ba3c75912d60e" or
        hash.md5(0, filesize) == "8d371f8a7a6dcc2655544ae13cbca03d" or
        hash.md5(0, filesize) == "09425f72de8bba18893dcd6f04115891" or
        hash.md5(0, filesize) == "26a0f7cdb9f7dc5ace9a40af825b1538" or
        hash.md5(0, filesize) == "2d69812584269699fade26622e6490c5" or
        hash.md5(0, filesize) == "7df1049cbd56c0bfa4a3364a379b4c2c" or
        hash.md5(0, filesize) == "9f15fe9c4415cd668334339f705b94d8" or
        hash.md5(0, filesize) == "fb90887592655a8c989e443c640167aa" or
        hash.md5(0, filesize) == "6791dad263cac6d63ebba6a4b57e7d71" or
        hash.md5(0, filesize) == "3ded1d71a822b53b12c3b67bcaf633f5" or
        hash.md5(0, filesize) == "781ce50001d4b449600afa347c9b0208" or
        hash.md5(0, filesize) == "8e84b01d5ac9624f0b181ade0e737193" or
        hash.md5(0, filesize) == "980e2134679bc0c609f7659882883d77" or
        hash.md5(0, filesize) == "4203ec932bfcc0907f91732440d6d997" or
        hash.md5(0, filesize) == "eb760d5c88f13f7ee0f8f86ba3407123" or
        hash.md5(0, filesize) == "f9f70096aabb4d22a6657014f4853a53" or
        hash.md5(0, filesize) == "3deeed48fd38f22e369f5c3092bd68a1" or
        hash.md5(0, filesize) == "f97d24212fa6a21be0c4d211e10f044c" or
        hash.md5(0, filesize) == "00d12d842596bf5ee1805effb4571d30" or
        hash.md5(0, filesize) == "9a0043d900a9ac78c886c59c9a328fd0" or
        hash.md5(0, filesize) == "7212229c85852c3bffaf9740002b2f39" or
        hash.md5(0, filesize) == "c53d0ea45dbc622afb7f16ea3eec78bc" or
        hash.md5(0, filesize) == "fc3ba5ed282d77127efd0b0f2403531b"
}

