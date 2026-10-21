/*
  Self-check
  [x] Every string has a provenance comment
  [x] No source-code identifiers / compiled-away names
  [x] Hash-gated values use the hash constant, not the plaintext
  [x] No substring redundancy within any "N of" group
  [x] No generic string can trigger the rule alone
  [x] Description matches the condition
  [x] Open-source-tool features are not attributed to the actor
  [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
  [x] No generic padding is required by the condition
  [x] No empty meta fields
*/
rule APT_GamblingGoblin_AlphaAgent_Oct2026
{
    meta:
        description = "Detects the AlphaAgent backdoor from the Gambling Goblin toolkit, identified by a unique, high-entropy salt used for device ID generation. This string is a strong indicator."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/gaming-the-system-how-a-chinese-speaking-actor-turned-brazilian-government-sites-into-an-seo-weapon/"
        date = "2026-10-16"
        hash1 = "232ef6be134c2b7c14648aa193daf7e23e987477b8a40150dd77883947fdf017"
        hash2 = "088d0742a667f1acfc83edb94671a10b951f6745badec6d5c754ef594dddf815"
        hash3 = "88544d36beb6dc621c9376806836d0ad109ece64b589605d5674e0c86313d1c0"
        hash4 = "9d3085eac9a59a94f0473db5ec0173def8777d2f794da281fb1749389ae33cdb"
        hash5 = "263c14e84398339b25cd3e59da7e108340306fdbb8112bbe7dc0f07a71eb8a31"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1"

    strings:
        $x1 = "e*f#1%0d$6&5=6" ascii  // source: explicit_literal

    condition:
        uint32(0) == 0x464c457f and filesize < 10MB and
        $x1
}
