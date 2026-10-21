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
rule APT_Lazarus_KANDYKORN_HLoader_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-18"
        description = "Detects the HLOADER persistence loader component of the KANDYKORN malware family, used by the Lazarus Group. The rule matches on a unique self-signed adhoc identifier."
        malware_family = "KANDYKORN"
        threat_actor = "Lazarus Group"
        hash1 = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "HLOADER-5555494485b460f1e2343dffaef9b94d01136320" ascii // source: figure_or_disassembly

    condition:
        uint32(0) == 0xfeedfacf and filesize < 5MB and
        $x1
}
