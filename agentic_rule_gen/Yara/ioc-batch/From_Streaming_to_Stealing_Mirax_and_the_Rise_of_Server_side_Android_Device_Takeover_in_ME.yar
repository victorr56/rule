// From Streaming to Stealing: Mirax and the Rise of Server-side Android Device Takeover in META
// Source: group-ib | https://www.group-ib.com/blog/mirax-android-device-takeover-rat/

import "hash"

rule IOC_From_Streaming_to_Stealing_Mirax_and_the_Rise_of_Server_side_Android_Device_Takeover_in_ME_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: From Streaming to Stealing: Mirax and the Rise of Server-side Android Device Takeover in META. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/mirax-android-device-takeover-rat/"
        date        = "2026-11-05"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "b9e84889c9760460f53c9b49cb43a636bb721d28" or
        hash.sha1(0, filesize) == "8531fe2db41e9e08525080be6d3e8092c5ffa5f8" or
        hash.sha1(0, filesize) == "0d83344fee8973165e5009768c1752095a57f3c1" or
        hash.sha1(0, filesize) == "3a1f9060dad56cd08e87fcafa2c87b99295b3db3" or
        hash.sha1(0, filesize) == "413e1c8661ec11fc8e7f9a7caccfc9c54cb1ea3d" or
        hash.sha1(0, filesize) == "c8f5abb80e9c936d6bd5da99c10e829cde69a8f5" or
        hash.sha1(0, filesize) == "20068b91036145b3e1b1d7e294b7a2f5ba26bd7f" or
        hash.sha1(0, filesize) == "b164a1bf2c7b478ce040e479377526c00885ab7f"
}

