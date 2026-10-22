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
rule MAL_SUDDENICON_Windows_Oct2026 {
    meta:
        description = "Detects SUDDENICON Windows components. The rule may fire on the static RC4 key or a combination of artifacts related to the 3CX supply chain compromise."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/elastic-users-protected-from-suddenicon-supply-chain-attack"
        date = "2026-10-22"
        hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
        hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
        hash3 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"
        hash4 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $s2, $s3, $s4"

    strings:
        // Strong anchor: high-entropy key, can fire alone
        $x1 = "3jB(2bsG#@c7" ascii  // source: explicit_literal

        // Supporting strings: require 3 of these to fire
        $s1 = "3CX Ltd" ascii wide  // source: figure_or_disassembly
        $s2 = "Windows.Trojan.SuddenIcon" ascii wide  // source: explicit_literal
        $s3 = "ffmpeg.dll" ascii wide  // source: prose
        $s4 = "raw.githubusercontent.com" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            $x1 or
            3 of ($s*)
        )
}
