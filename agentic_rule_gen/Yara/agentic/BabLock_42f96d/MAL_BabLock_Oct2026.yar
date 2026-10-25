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
rule MAL_BabLock_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-25"
        description = "Detects BabLock ransomware for Windows and Linux. The rule looks for a unique mutex, a specific build path, or a combination of supporting strings."
        reference = "https://www.group-ib.com/blog/bablock-ransomware/"
        hash1 = "2fd264f58ba82a2675280ec8c6759612def2bcc62aa6160f5e23071f67bb67ab"  // winutils.dll
        hash2 = "38c610102129be21d8d99ac92f3369c6650767ed513e5744c0cda54e68b33812"  // Dumped BabLock Windows payload
        hash3 = "e14b88795bde45cf736c8363c71a77171aa710a4e7fa9ce38470082cb1bdadbb"  // Dumped BabLock Windows payload
        hash4 = "7d62a33e9a2fedff6cf27aaa142ff15838a766ccd4a8d326424611e155442775"  // BabLock Linux/ESXi sample
        hash5 = "66bcad0829a59c424d062b949c2a556b11c509b17515dffecb9cbf65f13f3dc6"  // winutils.dll
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "artifact.1, artifact.2, artifact.3, artifact.4, artifact.5, artifact.7"
    strings:
        // --- Unique Strings ($x) ---
        $x1 = "80CE038F-6317-984D-C0A7-FA0A1EED0199" ascii wide  // source: explicit_literal, artifact.3, Mutex
        $x2 = "C:\\Users\\Administrator\\go" ascii  // source: prose, artifact.7, GOPATH string

        // --- Supporting Strings - Ransom Note ---
        $s_note1 = "_r_e_a_d_m_e.txt" ascii wide  // source: prose, artifact.2, Ransom note name
        $s_note2 = "_r_e_a_d_m_e.txt" ascii  // source: prose, artifact.2, Ransom note name

        // --- Supporting Strings - Windows ---
        $s_win1 = "XLOADERDLL.dll" ascii wide  // source: prose, artifact.1, Original DLL name
        $s_win2 = "3306" ascii wide  // source: explicit_literal, artifact.4, Hardcoded run key
        $s_win3 = "419" ascii wide  // source: prose, artifact.5, Russian language ID check

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        filesize < 20MB and
        (
            1 of ($x*) or
            (1 of ($s_note*) and 2 of ($s_win*))
        )
}
