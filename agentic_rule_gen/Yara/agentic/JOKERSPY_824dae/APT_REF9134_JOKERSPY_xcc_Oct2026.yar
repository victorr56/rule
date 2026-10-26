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
rule APT_REF9134_JOKERSPY_xcc_Oct2026
{
    meta:
        description = "Detects the JOKERSPY 'xcc' Mach-O binary used by REF9134."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/inital-research-of-jokerspy"
        date = "2026-10-26"
        hash1 = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3"

    strings:
        $x1 = "/Users/joker/Developer/Xcode/DerivedData/" ascii  // source: explicit_literal
        $x2 = "/Users/joker/Downloads/Spy/XProtectCheck/XProtectCheck/" ascii  // source: explicit_literal
        $x3 = "XProtectCheck-55554944f74096a836b73310bd55d97d1dff5cd4" ascii  // source: explicit_literal
        $x4 = "eck13XProtectCheck" ascii  // source: strings_listing
        $x5 = "kMDItemDisplayName = *TCC.db" ascii  // source: strings_listing


    condition:
        (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and
        filesize < 5MB and
        (1 of ($x*))
}
