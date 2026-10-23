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
rule MAL_BlackMatter_Linux_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-23"
        description = "Detects the Linux variant of BlackMatter ransomware. This rule may be triggered by a unique code sequence, a specific configuration key, or a combination of other configuration keys and section names."
        reference = "https://www.group-ib.com/blog/blackmatter2/"
        hash1 = "1247a68b960aa81b7517c614c12c8b5d1921d1d2fdf17be636079ad94caf970f"
        hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x2, s3, s4"

    strings:
        // Unique code sequence found in Linux variants
        $x1 = { 0F B6 10 84 D2 74 19 0F B6 34 0F 40 38 F2 74 10 48 83 C1 01 31 F2 48 83 F9 20 88 10 49 0F 44 C9 48 83 C0 01 4C 39 C0 75 D7 }  // source: figure_or_disassembly
        // Unique configuration string, strong anchor due to length
        $x2 = "worker-concurrency" ascii  // source: explicit_literal

        // Supporting strings: ELF section names and configuration keys
        $s1 = ".app.version" ascii  // source: figure_or_disassembly
        $s2 = ".cfgETD" ascii  // source: figure_or_disassembly
        $s3 = "bot-id" ascii  // source: explicit_literal
        $s4 = "kill-vm" ascii  // source: explicit_literal

    condition:
        uint32(0) == 0x464c457f and // ELF magic
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
