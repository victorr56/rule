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
rule APT_DPRK_FamousChomilla_Activity_Artifacts_Oct2026
{
    meta:
        description = "Detects artifacts associated with FAMOUS CHOMILLA (DPRK) fraudulent remote worker activity. The rule requires at least three suspicious strings, which can include VDO.Ninja URL fragments, typos, or a specific location name found in forged documents."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/huntress-dprk-remote-worker-investigation"
        date = "2026-10-31"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s5"

    strings:
        $s1 = "vdo.ninja/?push=" ascii  // source: figure_or_disassembly
        $s2 = "&screenshare&label=host" ascii  // source: figure_or_disassembly
        $s3 = "dlutter" ascii  // source: figure_or_disassembly
        $s4 = "hassic" ascii  // source: figure_or_disassembly
        $s5 = "Songgang Police Station" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        3 of ($s*)
}
