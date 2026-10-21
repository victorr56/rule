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
rule APT_Lazarus_KANDYKORN_RAT_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-18"
        description = "Detects the KANDYKORN RAT payload, used by the Lazarus Group. The rule requires 3 of several unique internal command names and C2-related artifacts."
        malware_family = "KANDYKORN"
        threat_actor = "Lazarus Group"
        hash1 = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 50
        unverified_strings = "s1, s2, s3, s5, s6"

    strings:
        $s1 = "resp_basicinfo" ascii // source: prose
        $s2 = "resp_file_zipdown" ascii // source: prose
        $s3 = "resp_cmd_create" ascii // source: prose
        $s4 = "bitscrunnch.linkpc.net" ascii // source: figure_or_disassembly
        $s5 = "/fP7savDX6c/bfC" ascii // source: prose
        $s6 = "group.pro-tokyo.top" ascii // source: prose

    condition:
        uint32(0) == 0xfeedfacf and filesize < 5MB and
        3 of ($s*)
}
