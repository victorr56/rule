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
rule APT_Lazarus_TouchShift_Loader_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects the TouchShift loader used by the Lazarus Group. The rule identifies a unique 16-byte XOR key hard-coded into the malware."
        family = "TechHub"
        reference = "https://securelist.com/lazarus-operation-flashhole/121541/"
        threat_actor = "Lazarus Group"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "x1"

    strings:
        $x1 = "x809G736iC3f8Wp8" ascii // source: explicit_literal, TouchShift hard-coded 16-byte XOR key.

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        $x1
}
