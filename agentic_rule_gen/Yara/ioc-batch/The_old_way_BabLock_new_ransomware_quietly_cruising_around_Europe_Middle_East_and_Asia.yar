// The old way: BabLock, new ransomware quietly cruising around Europe, Middle East, and Asia
// Source: group-ib | https://www.group-ib.com/blog/bablock-ransomware/

import "hash"

rule IOC_The_old_way_BabLock_new_ransomware_quietly_cruising_around_Europe_Middle_East_and_Asia_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: The old way: BabLock, new ransomware quietly cruising around Europe, Middle East, and Asia. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "group-ib"
        reference   = "https://www.group-ib.com/blog/bablock-ransomware/"
        date        = "2026-10-22"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d" or
        hash.sha256(0, filesize) == "2fd264f58ba82a2675280ec8c6759612def2bcc62aa6160f5e23071f67bb67ab" or
        hash.sha256(0, filesize) == "03c41019faf7e4cc26ca0dd3a2c41b2115e4c4ebd561402079bc4a20256c1813" or
        hash.sha256(0, filesize) == "88081a21e500e831d86666ca5d7a3d348f7c03bc5c471b6d17d8b18a022f25be" or
        hash.sha256(0, filesize) == "aa48acaef62a7bfb3192f8a7d6e5229764618ac1ad1bd1b5f6d19a78864eb31f" or
        hash.sha256(0, filesize) == "b99d114b267ffd068c3289199b6df95a9f9e64872d6c2b666d63974bbce75bf2" or
        hash.sha256(0, filesize) == "66bcad0829a59c424d062b949c2a556b11c509b17515dffecb9cbf65f13f3dc6" or
        hash.sha256(0, filesize) == "38c610102129be21d8d99ac92f3369c6650767ed513e5744c0cda54e68b33812" or
        hash.sha256(0, filesize) == "e14b88795bde45cf736c8363c71a77171aa710a4e7fa9ce38470082cb1bdadbb" or
        hash.sha256(0, filesize) == "7d62a33e9a2fedff6cf27aaa142ff15838a766ccd4a8d326424611e155442775" or
        hash.sha256(0, filesize) == "83052cc23c45ecaa09fe5c87fd650c7f8e708aea46756a2b9d452d40ce3b9c00" or
        hash.sha256(0, filesize) == "b711579e33b0df2143c7cb61246233c7f9b4d53db6a048427a58c0295d8daf1c"
}

