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
rule MAL_EtherRAT_Oct2026
{
    meta:
        description = "Detects the EtherRAT payload by its unique hardcoded build identifier. EtherRAT was observed being delivered by installers similar to those used for Potemkin."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack"
        date = "2026-10-17"
        hash1 = "2ada24dd6e517f37942b749c2bd57ddd97445e9853002cee70a0bc30d0b0ce3a"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1"

    strings:
        // GUID-like build identifier, strong anchor
        $x1 = "ab653feb-9e78-4578-87ed-2e30329fe858" ascii wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and $x1
}
