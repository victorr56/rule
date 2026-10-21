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
rule MAL_RMMProject_RAT_Oct2026
{
    meta:
        description = "Detects the RMMProject RAT, a Lua-scriptable payload featuring credential theft and a hidden VNC module. The rule targets unique log messages and SQL queries for browser credential theft. A match requires one of the strong unique strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack"
        date = "2026-10-17"
        hash1 = "3b7ae925e2d64522b4f69b56285b05aeca8c5aab5ab46a9c02c4fafb69d881ce"
        hash2 = "cd4e5e2c65b1660470d3446539ee68adf5faeece3eaeb46583623be9911ee145"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x2, $x3"

    strings:
        $x1 = "[RTSC] OpenInputSocket: sending session_id=" ascii wide // source: strings_listing
        $x2 = "SELECT item1 FROM metadata WHERE id = 'password'" ascii wide // source: explicit_literal
        $x3 = "SELECT a11 FROM nssPrivate" ascii wide // source: explicit_literal
        $x4 = "kCookies: total_cookies=" ascii wide // source: strings_listing

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and 1 of ($x*)
}
