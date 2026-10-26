/*
 * Self-check
 * [x] Every string has a provenance comment
 * [x] No source-code identifiers / compiled-away names
 * [x] Hash-gated values use the hash constant, not the plaintext
 * [x] No substring redundancy within any "N of" group
 * [x] No generic string can trigger the rule alone
 * [x] Description matches the condition
 * [x] Open-source-tool features are not attributed to the actor
 * [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
 * [x] No generic padding is required by the condition
 * [x] No empty meta fields
 */
rule MAL_LOBSHOT_Oct2026 {
    meta:
        author = "ioc-yara-daily (agentic)"
        description = "Detects LOBSHOT malware, a hVNC tool used by TA505. This rule identifies the malware based on unique internal strings, an infection marker, and anti-emulation artifacts. A match is triggered by a combination of four or more supporting indicators."
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-security-labs-discovers-lobshot-malware"
        date = "2026-10-26"
        hash1 = "e4ea88887753a936eaf3361dcc00380b88b0c210dcbde24f8f7ce27991856bf6"
        malware_family = "LOBSHOT"
        threat_actor = "TA505"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s4, s7, s8, s9"

    strings:
        // All strings are supporting as none are strong enough to fire alone.
        $s1 = "HVNC Remote Control" ascii wide  // source: strings_listing
        $s2 = "Set clipboard text failed." ascii wide  // source: strings_listing
        $s3 = "OK %08lx %08lx %d" ascii wide  // source: strings_listing
        $s4 = "hmr_*.dat" ascii wide  // source: explicit_literal
        $s5 = "HAL9TH" ascii wide  // source: figure_or_disassembly
        $s6 = "JohnDoe" ascii wide  // source: figure_or_disassembly
        $s7 = "134a1160" ascii wide  // source: explicit_literal
        $s8 = "amydecke.website" ascii wide  // source: explicit_literal
        $s9 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Devices" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        4 of ($s*)
}
