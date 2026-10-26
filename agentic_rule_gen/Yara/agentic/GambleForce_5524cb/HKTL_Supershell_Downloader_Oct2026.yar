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
rule HKTL_Supershell_Downloader_Oct2026
{
    meta:
        description = "Detects a downloader for the 'supershell' tool, potentially used by actors like GambleForce, based on a specific URL path."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/gambleforce-gang/"
        date = "2026-10-26"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 55

    strings:
        $x1 = "/supershell/compile/download/linuxamdx64" ascii // source: figure_or_disassembly

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and filesize < 5MB and
        $x1
}
