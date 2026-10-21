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
rule MAL_MACOS_Stealer_V2_Oct2026 {
    meta:
        description = "Detects macos-stealer-v2, which uses osascript for credential phishing and exfiltrates data."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/10/introducing-macos-mirage.html.html"
        date = "2026-10-16"
        hash1 = "be77bca22f078d57058535ddcf26a39a752a8df030392cb45ba6a60e06651878"
        hash2 = "01f9a24bd868a856909db5eb61be6f30939e402fd7dd2e40180ffe2406de5c35"
        hash3 = "336c1ba08fb64d466e042e16f20bf0d1f3947e4430000be08c2b6698884de028"
        hash4 = "c363180da38cac9e894b158a65eb3ad72eb31c24a6b16c00bbc3bfc276db32d5"
        hash5 = "f7dcdc4167ec267aef007f9d5f98e9e0314185e5355effd3e304b6fa686ea84c"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, s1, s2, s3, s4, s5, s6, s7"

    strings:
        $x1 = "macos_osascript_credential_phishing" ascii  // source: explicit_literal

        $s1 = "Password Request" ascii  // source: prose
        $s2 = "/tmp/lksopo" ascii  // source: prose
        $s3 = "dscl . authonly" ascii  // source: prose
        $s4 = "~/.bhost" ascii  // source: prose
        $s5 = "~/.phost" ascii  // source: prose
        $s6 = "~/.username" ascii  // source: prose
        $s7 = "~/.pwd" ascii  // source: prose

    condition:
        (
            uint32(0) == 0xfeedface or // Mach-O 32-bit
            uint32(0) == 0xfeedfacf or // Mach-O 64-bit
            uint32(0) == 0xcafebabe or // Mach-O Universal
            uint32(0) == 0xcffaedfe    // Mach-O Universal 64-bit
        )
        and filesize < 20MB
        and (
            $x1 or
            3 of ($s*)
        )
}
