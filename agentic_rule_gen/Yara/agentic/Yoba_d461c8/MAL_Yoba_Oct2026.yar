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
import "pe"

rule MAL_Yoba_Oct2026
{
    meta:
        description = "Detects Yoba malware components. A match requires a combination of at least three strings or constants related to its XOR key, mutex, anti-analysis techniques, or region checks."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/"
        date = "2026-10-28"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "$s1, $s2, $s3"

    strings:
        // Conceptually unique, but from prose (unverified)
        $s1 = "IRANNUMBERONE" ascii wide  // source: prose, dropper XOR key
        $s2 = "Local\\WindowsSecurity" ascii wide  // source: prose, XMRig mutex

        // Supporting string from explicit literal (unverified)
        $s3 = "pddy" ascii wide  // source: explicit_literal, anti-analysis filler

        // Verified constants
        $c1 = { 49 E1 9E CF }  // source: hash_gated, DJB2("DebugObject"), little-endian
        $c2 = { 01 C8 00 04 EC }  // source: figure_or_disassembly, CIS check bitmask

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        3 of them
}
