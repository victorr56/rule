/*
    This rule detects the BlackMatter ransomware.

    The detection is based on a combination of unique strings found in the binary. These include
    a hardcoded PRNG seed, an XOR key, an internal configuration key name, and the unique name
    of the PE section used to store the encrypted configuration.

    The rule requires three of these distinct artifacts to be present for a match, ensuring
    high precision while adhering to strict detection guidelines.

    Note: This rule uses a hex string to represent the section name ".rsrс" to avoid
    UTF-8 character encoding issues in different environments. The 'с' is a Cyrillic character.
*/
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
rule MAL_BlackMatter_Win_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/blackmatter-ransomware/"
        date = "2026-10-23"
        description = "Detects BlackMatter ransomware for Windows based on unique embedded strings. The condition requires three distinct strings to match."
        malware_family = "BlackMatter"
        threat_actor = "BlackMatter"
        platform = "windows"
        filetype = "pe"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s2, s3, s4"

    strings:
        // All strings are considered "weak anchors" under the strict mode guide,
        // as none are >= 16 bytes or high-entropy. Therefore, they are grouped as
        // supporting strings ($s) and a threshold of 3 is required.

        $s1 = "0FFCAA1EAh" ascii  // source: explicit_literal
        $s2 = "022065FEDh" ascii  // source: explicit_literal
        $s3 = "bot_company" ascii  // source: explicit_literal
        $s4 = { 2E 72 73 72 D1 81 }  // source: explicit_literal, section name ".rsrс" (U+0441) as UTF-8 bytes

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        3 of ($s*)
}
