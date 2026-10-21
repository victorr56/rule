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
import "pe"
import "dotnet"

rule MAL_BTMOB_Builder_Oct2026 {
    meta:
        description = "Detects the .NET-based builder for the BTMOB Android RAT."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/malware/btmob-stealthy-rat-burrowing-deep-android-devices/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1"
    strings:
        $x1 = "MSIL/BtmobRat" ascii wide  // source: explicit_literal

        $s1 = "Anti-Delete" ascii wide  // source: figure_or_disassembly
        $s2 = "Anti-Kill" ascii wide  // source: figure_or_disassembly
        $s3 = "Anti-emulator" ascii wide  // source: figure_or_disassembly
        $s4 = "Fake uninstall" ascii wide  // source: figure_or_disassembly
        $s5 = "Complete hide" ascii wide  // source: figure_or_disassembly
        $s6 = "Hide permissions" ascii wide  // source: figure_or_disassembly
        $s7 = "Disable Google store" ascii wide  // source: figure_or_disassembly
        $s8 = "Capture lockscreen" ascii wide  // source: figure_or_disassembly
        $s9 = "Force permissions" ascii wide  // source: figure_or_disassembly
        $s10 = "Prevent sleep mode" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and dotnet.is_dotnet and
        (
            $x1 or
            4 of ($s*)
        )
}
