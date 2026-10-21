/*
  This rule is part of the ioc-yara-daily project.
  Get updates at https://github.com/ioc-yara-daily/yara-rules
*/
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
rule APT_FamousSparrow_SparroWocky_Backdoor_Oct2026
{
    meta:
        description = "Detects the SparroWocky backdoor used by FamousSparrow. A match requires a unique service description string, or any three supporting indicators, or a specific constant combined with two supporting indicators."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Unique, strong anchor
        $x1 = "Tracks process creation, termination, and related system audit events." ascii wide  // source: explicit_literal

        // Supporting indicators
        $s1 = "acdbcnus" ascii  // source: figure_literals, Fig 8. Custom initialization of Mbed TLS random bit generator
        $s2 = "SnapCart" ascii wide  // source: explicit_literal
        $s3 = "\\\\.\\pipe\\ccpipe" ascii wide  // source: explicit_literal
        $s4 = "MyMutexName" ascii wide  // source: explicit_literal
        $s5 = "MyEventName" ascii wide  // source: explicit_literal
        $s6 = "MySharedMemName" ascii wide  // source: explicit_literal

        // Constants
        $c1 = { 04 C0 40 00 }  // source: figure_literals, Fig 7. SparroWocky forges an LDR_DATA_TABLE_ENTRY structure
        $c2 = { 44 33 22 11 }  // source: explicit_literal
        $c3 = { 13 12 11 09 }  // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            $x1 or
            3 of ($s*) or
            (1 of ($c*) and 2 of ($s*))
        )
}
