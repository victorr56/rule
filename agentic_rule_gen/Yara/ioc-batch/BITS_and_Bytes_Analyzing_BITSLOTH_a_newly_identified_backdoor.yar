// BITS and Bytes: Analyzing BITSLOTH, a newly identified backdoor
// Source: elastic-security-labs | https://www.elastic.co/security-labs/threat-command/bits-and-bytes-analyzing-bitsloth

import "hash"

rule IOC_BITS_and_Bytes_Analyzing_BITSLOTH_a_newly_identified_backdoor_Hashes
{
    meta:
        description = "Exact file-hash match for hashes published in: BITS and Bytes: Analyzing BITSLOTH, a newly identified backdoor. Hashes are taken from the article as-is; the article may also list legitimate files it discusses (abused tools, drivers), so use for hunting, not blocking."
        author      = "ioc-yara-daily"
        source      = "elastic-security-labs"
        reference   = "https://www.elastic.co/security-labs/threat-command/bits-and-bytes-analyzing-bitsloth"
        date        = "2026-10-18"
        tlp         = "WHITE"
        status      = "untested"
        test_result = "exact-hash rule: matches exactly the listed files by construction; no sample was scanned"
        score       = 50
    condition:
        hash.sha256(0, filesize) == "4a4356faad620bf12ff53bcfac62e12eb67783bd22e66bf00a19a4c404bf45df" or
        hash.sha256(0, filesize) == "dfb76bcf5a3e29225559ebbdae8bdd24f69262492eca2f99f7a9525628006d88" or
        hash.sha256(0, filesize) == "4fb6dd11e723209d12b2d503a9fcf94d8fed6084aceca390ac0b7e7da1874f50" or
        hash.sha256(0, filesize) == "0944b17a4330e1c97600f62717d6bae7e4a4260604043f2390a14c8d76ef1507" or
        hash.sha256(0, filesize) == "0f9c0d9b77678d7360e492e00a7fa00af9b78331dc926b0747b07299b4e64afd"
}

