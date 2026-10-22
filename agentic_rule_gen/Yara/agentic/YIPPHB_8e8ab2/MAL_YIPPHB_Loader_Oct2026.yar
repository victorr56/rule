/* Self-check
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
rule MAL_YIPPHB_Loader_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/doing-time-with-the-yipphb-dropper"
        date = "2026-10-22"
        description = "Detects the YIPPHB loader component, which contains an obfuscated PowerShell script. A match is triggered by one unique hex string or a combination of three supporting strings."
        hash1 = "49562fda46cfa05b2a6e2cb06a5d25711c9a435b578a7ec375f928aae9c08ff2"
        malware_family = "YIPPHB"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s4"

    strings:
        $x1 = { 2d c2 af c2 af 2d 2d c2 af 2d 2d c2 af c2 af }  // ascii: "-¯¯--¯--¯¯", source: figure_or_disassembly

        $s1 = "NwgoxM.KPJaNj" ascii  // source: figure_or_disassembly
        $s2 = "PUlGKA" ascii  // source: figure_or_disassembly
        $s3 = "[system.Text.Encoding]::Unicode.GetString" ascii  // source: figure_or_disassembly
        $s4 = "_*\\/}+/_=" ascii  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 2MB and
        (
            $x1 or
            3 of ($s*)
        )
}
