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
rule APT_Citrus_Activity_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-11-11"
        description = "Detects tools and artifacts associated with Citrus group activity. The rule can be triggered by a unique hardcoded string or a combination of three supporting strings."
        reference = "https://securelist.com/citrus-ransomware/121879/"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        threat_actor = "Citrus"
        unverified_strings = "s2"

    strings:
        $x1 = "cdc:91.210.109.118" ascii wide  // source: figure_or_disassembly

        $s1 = { D0 98 D0 BC D1 8F 20 D1 83 D0 B7 D0 BB D0 B0 } // "Имя узла" in UTF-8  // source: figure_or_disassembly
        $s2 = "GHOSTAUFTAFGS" ascii wide  // source: prose
        $s3 = "mirror.yandex.ru" ascii wide  // source: figure_or_disassembly
        $s4 = "https://account.proton.me/mail/signup?plan=free" ascii wide  // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and
        filesize < 10MB and
        (
            $x1 or
            3 of ($s*)
        )
}
