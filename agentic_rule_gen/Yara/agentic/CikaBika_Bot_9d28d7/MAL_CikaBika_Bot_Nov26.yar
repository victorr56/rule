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
rule MAL_CikaBika_Bot_Nov26
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-11-02"
        description = "Detects CikaBika Bot, a Rust-based RAT that uses Discord for C2. The rule targets strings related to commands, output filenames, and a UAC bypass technique. A match requires at least three of these strings to be present."
        reference = "https://www.darktrace.com/blog/cikabika-bot-inside-a-discord-rat"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s4, s5, s6, s7, s8, s9"

    strings:
        // Figure-based strings from the report
        $s1 = "!sysinfo" ascii wide  // source: figure_or_disassembly
        $s2 = "!shell" ascii wide  // source: figure_or_disassembly
        $s3 = "!isOn" ascii wide  // source: figure_or_disassembly

        // Prose-based strings, potentially less reliable
        $s4 = "!src" ascii wide  // source: prose
        $s5 = "!camera" ascii wide  // source: prose
        $s6 = "tasklist_startup.txt" ascii wide  // source: prose
        $s7 = "network_info.txt" ascii wide  // source: prose
        $s8 = "screenshot.png" ascii wide  // source: prose
        $s9 = "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        3 of ($s*)
}
