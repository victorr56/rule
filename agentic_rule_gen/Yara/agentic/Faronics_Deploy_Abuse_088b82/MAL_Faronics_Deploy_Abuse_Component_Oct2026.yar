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
rule MAL_Faronics_Deploy_Abuse_Component_Oct2026
{
    meta:
        description = "Detects components related to the abuse of Faronics Deploy, containing a specific attacker identifier."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/faronics-deploy-abuse"
        date = "2026-10-31"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1"

    strings:
        $x1 = "6D70CDEF-CFF4-48A7-8092-24E5B9C3FA1D" ascii wide // source: prose, from URL in report

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        $x1
}
