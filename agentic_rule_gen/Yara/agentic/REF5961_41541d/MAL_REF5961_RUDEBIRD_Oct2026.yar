/*
 * This rule detects the RUDEBIRD malware, part of the REF5961 intrusion set's toolset.
 *
 * Self-check
 * [x] Every string has a provenance comment
 * [x] No source-code identifiers / compiled-away names
 * [x] Hash-gated values use the hash constant, not the plaintext
 * [x] No substring redundancy within any "N of" group
 * [x] No generic string can trigger the rule alone
 * [x] Description matches the condition
 * [x] Open-source-tool features are not attributed to the actor
 * [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
 * [x] No generic padding is required by the condition
 * [x] No empty meta fields
 */
rule MAL_REF5961_RUDEBIRD_Oct2026
{
    meta:
        description = "Detects RUDEBIRD malware used by the REF5961 intrusion set. A match is based on a unique code sequence provided in the report's YARA signature for RUDEBIRD."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/introducing-the-ref5961-intrusion-set"
        date = "2026-10-18"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2"

    strings:
        $x1 = { 40 53 48 83 EC 20 48 8B D9 B9 D8 00 00 00 E8 FD C1 FF FF 48 8B C8 33 C0 48 85 C9 74 05 E8 3A F2 }  // source: strings_listing


    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        $x1
}
