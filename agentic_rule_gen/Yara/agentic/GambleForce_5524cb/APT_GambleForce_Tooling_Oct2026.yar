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
rule APT_GambleForce_Tooling_Oct2026
{
    meta:
        description = "Detects GambleForce tooling, such as scripts or configuration files, based on a combination of actor-specific strings like profile names, passwords, and usernames."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/gambleforce-gang/"
        date = "2026-10-26"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50

    strings:
        $s1 = "cs2.profile" ascii  // source: figure_or_disassembly
        $s2 = "qwertyuiop123" ascii  // source: figure_or_disassembly
        $s3 = "sbsbsb22" ascii  // source: figure_or_disassembly
        $s4 = "nmgb" ascii  // source: figure_or_disassembly
        $s5 = "neo2323" ascii  // source: figure_or_disassembly

    condition:
        filesize < 1MB and
        3 of ($s*)
}
