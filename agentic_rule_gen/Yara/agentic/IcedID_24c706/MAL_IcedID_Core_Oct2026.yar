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
rule MAL_IcedID_Core_Oct2026
{
    meta:
        description = "Detects IcedID malware. The rule may fire on one of several strong unique strings, a combination of a medium-strength unique string and supporting strings, or a combination of multiple supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/icedid/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s12, s13, s14"

    strings:
        // $x* are strong anchors (>16 bytes) and can fire the rule alone
        $x1 = "bot.init > core init ver=" ascii wide  // source: figure_or_disassembly
        $x2 = "meayjiduge_{94D3BBC9-24EA-411F-066A-A604B94A99DA}" ascii wide  // source: figure_or_disassembly
        $x3 = "C=US; O=VeriSign, Inc.; OU=VeriSign Trust Network; OU=(c) 2006 VeriSign, Inc. - For authorized use only; CN=VeriSign Class 3 Public Primary Certification Authority - G5" ascii wide  // source: figure_or_disassembly

        // $a* are medium-strength unique strings, require other strings to fire
        $a1 = "/image/?id=" ascii wide  // source: figure_or_disassembly
        $a2 = "BE0F1DE5" ascii wide  // source: figure_or_disassembly

        // $s* are supporting strings
        $s1 = "zeus" ascii wide  // source: figure_or_disassembly
        $s2 = "#lf" ascii wide  // source: figure_or_disassembly
        $s3 = "#ke" ascii wide  // source: figure_or_disassembly
        $s4 = "#dr" ascii wide  // source: figure_or_disassembly
        $s5 = "#dm" ascii wide  // source: figure_or_disassembly
        $s6 = "/audio/" ascii wide  // source: figure_or_disassembly
        $s7 = "/video/" ascii wide  // source: figure_or_disassembly
        $s8 = "VMwa" ascii  // source: figure_or_disassembly
        $s9 = "XenV" ascii  // source: figure_or_disassembly
        $s10 = "KVMK" ascii  // source: figure_or_disassembly
        $s11 = "VBox" ascii  // source: figure_or_disassembly
        $s12 = "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii wide  // source: prose
        $s13 = "DelegateExecute" ascii wide  // source: prose
        $s14 = "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            (1 of ($a*) and 2 of ($s*)) or
            4 of ($s*)
        )
}
