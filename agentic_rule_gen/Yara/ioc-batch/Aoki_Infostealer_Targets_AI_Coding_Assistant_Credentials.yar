// Aoki: Infostealer Targets AI Coding Assistant Credentials
// Source: symantec-threat-hunter | https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting

import "hash"

rule IOC_Aoki_Infostealer_Targets_AI_Coding_Assistant_Credentials_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: Aoki: Infostealer Targets AI Coding Assistant Credentials. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "symantec-threat-hunter"
        reference   = "https://www.security.com/threat-intelligence/aoki-infostealer-ai-targeting"
        date        = "2026-10-15"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69" or
        hash.sha256(0, filesize) == "bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf" or
        hash.sha256(0, filesize) == "0adc8e83b2416c275b1283916d70568faddeb6d718eb45f9addfb0938db245b3" or
        hash.sha256(0, filesize) == "6655b89b9885483d459c73f2a52e3cec121de5c5956172a8676a0f4c2de94999"
}

