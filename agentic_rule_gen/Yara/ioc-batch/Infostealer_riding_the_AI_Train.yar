// Infostealer riding the AI Train
// Source: checkpoint-research | https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/

import "hash"

rule IOC_Infostealer_riding_the_AI_Train_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Infostealer riding the AI Train. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "checkpoint-research"
        reference   = "https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/"
        date        = "2026-10-24"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha1(0, filesize) == "007137599bc4d69ee952a5228b5fcb2c3b9a95a7" or
        hash.sha1(0, filesize) == "00d52c7e759d878f0d8a117502f6d854af13f007" or
        hash.sha1(0, filesize) == "04eddccb79db41e03a4ee8542e8a33d7f1d9fe18" or
        hash.sha1(0, filesize) == "057a2d1dedeb93b7765c455a9e0c469e7cbe4843" or
        hash.sha1(0, filesize) == "079ddf5cc7d6ca2e02f860f87d4d18c83db9d331" or
        hash.sha1(0, filesize) == "0b74ce90a39278fb97fe94f6306af71cbe679503" or
        hash.sha1(0, filesize) == "0c46ac5555cf8f305c1345a21d0802c52bf52cd8" or
        hash.sha1(0, filesize) == "0d8d0bad2e08856ba379e425e2e90e49506af631"
}

