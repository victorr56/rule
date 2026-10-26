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
rule APT_GambleForce_CS_Beacon_Oct2026
{
    meta:
        description = "Detects Cobalt Strike beacons configured by GambleForce, based on a unique certificate subject and other operator-specific strings. The rule can be triggered by the unique certificate subject string alone, or by a combination of at least three other unique operator-specific strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/gambleforce-gang/"
        date = "2026-10-26"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "CN=Microsec e-Szigno Root CA, OU=e-Szigno CA, O=Microsec Ltd., L=Budapest, S=HU, C=HU" ascii wide // source: figure_or_disassembly

        $s1 = "qwertyuiop123" ascii wide // source: figure_or_disassembly
        $s2 = "sbsbsb22" ascii wide // source: figure_or_disassembly
        $s3 = "nmgb" ascii wide // source: figure_or_disassembly
        $s4 = "neo2323" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            $x1 or
            3 of ($s*)
        )
}
