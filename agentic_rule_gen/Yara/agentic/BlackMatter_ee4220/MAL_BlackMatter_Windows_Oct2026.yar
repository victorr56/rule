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
rule MAL_BlackMatter_Windows_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-23"
        description = "Detects the Windows variant of BlackMatter ransomware. This rule may be triggered by unique code sequences, a specific PRNG seed string, or a combination of several distinctive configuration and API strings."
        reference = "https://www.group-ib.com/blog/blackmatter2/"
        hash1 = "072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486"
        hash2 = "7c642cdeaa55f56c563d82837f4dc630583b516a5d02d5a94b57b65489d74425"
        hash3 = "6d4712df42ad0982041ef0e2e109ab5718b43830f2966bd9207a7fac3af883db"
        hash4 = "2466fca0e29b06c78ffa8a44193fb58c30e6bec4e54bbef8e6622349b95cce4c"
        hash5 = "0751c422962dcd500d7cf2cf8bf544ddf5b2fe3465df7dd9b9998f6bba5e08a4"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x4, s1, s2, s3, s4"

    strings:
        // Unique code sequences found in Windows variants
        $x1 = { 80 C6 61 80 EE 61 C1 CA 0D 03 D0 }  // source: figure_or_disassembly
        $x2 = { 02 F1 2A F1 B9 0D 00 00 00 D3 CA 03 D0 }  // source: figure_or_disassembly
        $x3 = { 3C 2B 75 04 B0 78 EB 0E 3C 2F 75 04 B0 69 EB 06 3C 3D 75 02 B0 7A }  // source: figure_or_disassembly
        // PRNG seed string, strong anchor due to length and uniqueness
        $x4 = "0F8B2AB512017D0F5" ascii wide  // source: explicit_literal

        // Supporting strings
        $s1 = "bot_company" ascii wide  // source: explicit_literal
        $s2 = "ICMLuaUtil" wide  // source: prose
        $s3 = "PORTPROMPT:" ascii wide  // source: prose
        $s4 = "XPSPort:" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
