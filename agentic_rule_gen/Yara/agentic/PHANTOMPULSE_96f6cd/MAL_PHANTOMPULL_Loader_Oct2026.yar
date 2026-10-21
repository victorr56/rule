/*
 Self-check
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
rule MAL_PHANTOMPULL_Loader_Oct2026
{
    meta:
        description = "Detects PHANTOMPULL, a loader used by REF6598 to deploy the PHANTOMPULSE RAT. The rule matches on unique encryption keys, code patterns, and strings. A match is triggered by a unique key, code pattern, or download path, or by a combination of a specific mutex, status endpoint, and a hash seed."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/phantom-in-the-vault"
        date = "2026-10-17"
        hash1 = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3, x4, s2, c1"

    strings:
        // --- Strong Anchors ($x*) ---
        $x1 = { 6a85736b64761a8b2aaeadc1c0087e1897d16cc5a9d49c6a6ea1164233bad206 } // source: explicit_literal, AES-256-CBC key
        $x2 = { A6FA4ADFC20E8E6B77E2DD631DC8FF18 } // source: explicit_literal, AES-256-CBC IV
        $x3 = { f77c8e40dfc17be5e74d8679d5b35341 } // source: explicit_literal, 16-byte rotating key
        $x4 = { dcf5a9b27cbeedb769ccc8635d204af9 } // source: explicit_literal, 16-byte XOR key for final payload
        $x5 = { 45 8B 0C 83 41 BA A7 C6 67 4E 49 01 C9 45 8A 01 } // source: strings_listing, PHANTOMPULL djb2 hashing routine
        $x6 = "/syncobs.exe?q=%23OBSIDIAN" ascii // source: figure_or_disassembly, download path
        $x7 = { 48 83 C4 80 FF 15 ?? ?? ?? ?? 83 F8 FE 75 } // source: strings_listing, unreachable GetTickCount check

        // --- Supporting ($s*) ---
        $s1 = "/stuk-phase" ascii // source: figure_or_disassembly, status endpoint
        $s2 = "hVNBUORXNiFLhYYh" ascii // source: prose, PHANTOMPULL second stage mutex

        // --- Constants ($c*) ---
        $c1 = { A7 C6 67 4E } // source: explicit_literal, djb2 hash seed 0x4E67C6A7, little-endian

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB
        and (
            1 of ($x*)
            or (2 of ($s*) and $c1)
        )
}
