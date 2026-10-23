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
rule APT_OldGremlin_TinyFluff_Oct2026
{
    meta:
        description = "Detects the TinyFluff backdoor, a custom Node.js-based implant used by the OldGremlin ransomware group. The rule detects based on a unique public key or a combination of a hardcoded RC4 key and at least two other supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.group-ib.com/blog/oldgremlin-comeback/"
        date = "2026-10-23"
        hash1 = "4682A66EFA7C79AB56DFDFC1BBA5CF001D380D516FF1B64ACEA0B53784FDE8CC"
        hash2 = "8f3747775a1bdeae4627763687bdcb2ef325874e7a908f3ec24380c5d2f2b44a"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$s1, $s2, $s3, $s4, $s5, $s6"

    strings:
        // $x* are strong unique strings that can fire with high confidence
        $x1 = "MCowBQYDK2VwAyEAgp0p9o6lg/ZZ3WUJtx7UBBb1qYMZEDNC19Hbb84wt88=" ascii  // source: figure_or_disassembly

        // $a* are unique anchors that need some company
        $a1 = "lin9gtmn" ascii  // source: figure_or_disassembly

        // $s* are supporting strings, plausible but not unique alone
        $s1 = "TinyFluff" ascii wide  // source: prose
        $s2 = ".download:" ascii wide  // source: prose
        $s3 = "nodejs.org/dist/latest-erbium/win-x86/node.exe" ascii wide  // source: prose
        $s4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid" ascii wide  // source: prose
        $s5 = "NESC" ascii wide  // source: prose
        $s6 = "FWSE" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        (
            $x1 or
            ($a1 and 2 of ($s*))
        )
}
