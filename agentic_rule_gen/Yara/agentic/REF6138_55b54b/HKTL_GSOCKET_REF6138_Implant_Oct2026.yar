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
rule HKTL_GSOCKET_REF6138_Implant_Oct2026
{
    meta:
        description = "Detects the GSOCKET secure socket tool by matching a unique error string. A version of this tool was observed being used by REF6138."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/betting-on-bots"
        date = "2026-10-17"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "gsocket: gs_funcs not found" ascii  // source: strings_listing

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        $x1
}
