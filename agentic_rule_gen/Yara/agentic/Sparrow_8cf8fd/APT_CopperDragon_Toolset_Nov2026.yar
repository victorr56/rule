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
rule APT_CopperDragon_Toolset_Nov2026
{
    meta:
        description = "Detects various tools associated with the CopperDragon threat actor, such as SquadC, CopperLsass, and SilentDelivery components. The rule can be triggered by unique lure names and certificate fingerprints, or a combination of four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        date = "2026-11-11"
        hash1 = "715c206629f59ff5b0134a33362162ce7a40a9b25aa17f0543dc9648d51a67cf"
        hash2 = "8bbc395a7a0faff074c6e31c7da37bf1540a4e7ec3d80870f8d6bd1f5d4cecbb"
        hash3 = "1cd0c608418cca80149ef3077e54969f24cd7ef3f22707cb280fa4b378ffa76b"
        hash4 = "40880b6fce6f83df4e902cd29d7abb303ffa3f37c429c382f2aaeea34f7be074"
        hash5 = "4cafda69af3179ceb4a1f5ed864c501279796254709c86ca236be1cf74a8643f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$s1"

    strings:
        // Unique strings
        $x1 = "Strategi_AS_Referensi_April2026.rar" ascii wide  // source: explicit_literal
        $x2 = "760be920fad07881b8ce9d94e074a35b4f806717" ascii  // source: explicit_literal
        $x3 = "ee4a8b81fe3864582efc27a77f806990e2602dcc36447ddda4b3a230a473d575" ascii  // source: explicit_literal

        // Supporting strings
        $s1 = "WindowsUpdateAssist" ascii wide  // source: prose
        $s2 = "SquadC" ascii wide  // source: figure_or_disassembly
        $s3 = "slave.dll" ascii wide  // source: explicit_literal
        $s4 = "/image-check" ascii  // source: explicit_literal
        $s5 = "/report-url" ascii  // source: explicit_literal
        $s6 = "/register-ip" ascii  // source: explicit_literal
        $s7 = "kbl" ascii wide  // source: explicit_literal
        $s8 = "ss1" ascii wide  // source: explicit_literal
        $s9 = "CN=8.8.8.8" ascii  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
