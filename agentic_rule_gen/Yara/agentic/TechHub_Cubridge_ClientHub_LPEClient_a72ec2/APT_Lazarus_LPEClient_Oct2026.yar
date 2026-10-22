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
rule APT_Lazarus_LPEClient_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects the LPEClient malware component used by the Lazarus Group. The rule matches on combinations of unique message ID constants and the name of the 'Threefish' cipher used by the malware. A match requires at least three message IDs, or two message IDs and the cipher name string."
        family = "LPEClient"
        reference = "https://securelist.com/lazarus-operation-flashhole/121541/"
        threat_actor = "Lazarus Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "c1, c2, c3, c4, s1"

    strings:
        $c1 = { 34 6B 7D F0 } // source: explicit_literal, LPEClient message ID for initial data collection (0xF07D6B34).
        $c2 = { 78 F2 9C A3 } // source: explicit_literal, LPEClient message ID for key exchange request (0xA39CF278).
        $c3 = { 51 0D 8C EF } // source: explicit_literal, LPEClient message ID for transmitting post-quantum ciphertexts (0xEF8C0D51).
        $c4 = { 25 0A 79 CB } // source: explicit_literal, LPEClient message ID sent after successful payload loading (0xCB790A25).

        $s1 = "Threefish" ascii // source: prose, Tweakable block cipher used by LPEClient to decrypt payloads.

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            3 of ($c*) or
            (2 of ($c*) and $s1)
        )
}
