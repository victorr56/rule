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
rule MAL_PHANTOMPULSE_RAT_Oct2026
{
    meta:
        description = "Detects the PHANTOMPULSE RAT, used by REF6598. The rule targets unique debug strings found in the binary, and includes a speculative clause for a potential macOS variant using command hash constants and a persistence filename. A match requires one of the unique debug strings, or for the macOS variant, the plist filename and two command hash constants."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault"
        date = "2026-10-17"
        hash1 = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1"

    strings:
        // --- Strong Anchors ($x*) ---
        $x1 = "[UNINSTALL 2/6] Removing Scheduled Task..." ascii wide // source: strings_listing, debug string
        $x2 = "PhantomInject: host PID=%lu" ascii wide // source: strings_listing, debug string
        $x3 = "inject: shellcode detected -> InjectShellcodePhantom" ascii wide // source: strings_listing, debug string

        // --- Supporting ($s*) ---
        $s1 = "com.vfrfeufhtjpwgray.plist" ascii // source: prose, macOS persistence LaunchAgent plist file name

        // --- Constants ($c*) ---
        $c1 = { 42 11 CF 04 } // source: hash_gated, djb2("inject"), little-endian
        $c2 = { 83 F0 37 9A } // source: hash_gated, djb2("screenshot"), little-endian
        $c3 = { FF 51 E2 4E } // source: hash_gated, djb2("uninstall"), little-endian

    condition:
        (
            uint16(0) == 0x5a4d // PE
            or uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe // Mach-O
        )
        and filesize < 20MB
        and (
            1 of ($x*)
            or ($s1 and 2 of ($c*))
        )
}
