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
rule MAL_GHOSTPULSE_Loader_Oct2026
{
    meta:
        description = "Detects the GHOSTPULSE loader component by requiring a combination of two specific constants and a hardcoded filename."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        date = "2026-10-26"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 50
        unverified_strings = "c2, s1"

    strings:
        $c1 = { 3F 00 01 00 }  // source: figure_or_disassembly, multiplier constant
        $c2 = { B4 D3 B2 A1 }  // source: explicit_literal, key generation constant
        $s1 = "handoff.wav" ascii wide  // source: prose, payload filename

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        $c1 and $c2 and $s1
}
