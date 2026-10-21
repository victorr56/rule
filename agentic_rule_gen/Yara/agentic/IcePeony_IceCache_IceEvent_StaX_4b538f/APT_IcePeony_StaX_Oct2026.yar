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
rule APT_IcePeony_StaX_Oct2026
{
    meta:
        description = "Detects StaX, a customized Stowaway variant used by IcePeony. The rule targets a hardcoded key and unique function names. This rule will fire on one unique identifier or a combination of four supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "http://nao-sec.org/2024/10/IcePeony-with-the-996-work-culture.html"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Unique hardcoded key and function names
        $x1 = "sOIEU1DF9pDpLeXjPtDRbLnnGRJPuTP9tsNwmSYauDzhPF-g1kYE1ceYCK8" ascii  // source: figure_or_disassembly
        $x2 = "StaX_agent_initial_achieveUUID" ascii  // source: strings_listing
        $x3 = "StaX_agent_initial_NormalPassive_func1" ascii  // source: strings_listing
        $x4 = "StaX_agent_initial_init_0_func1" ascii  // source: strings_listing
        $x5 = "StaX_crypto_KeyPadding" ascii  // source: figure_or_disassembly
        $x6 = "StaX_crypto_AESDecrypt" ascii  // source: figure_or_disassembly

        // Supporting function names
        $s1 = "StaX_agent_initial_ModeMonitor" ascii  // source: strings_listing
        $s2 = "StaX_agent_initial_NormalActive" ascii  // source: strings_listing
        $s3 = "StaX_agent_initial_ParseOptions" ascii  // source: strings_listing
        $s4 = "StaX_agent_initial_checkOptions" ascii  // source: strings_listing

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($s*)
        )
}
