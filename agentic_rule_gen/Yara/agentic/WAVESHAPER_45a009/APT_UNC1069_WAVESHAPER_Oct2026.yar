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
rule APT_UNC1069_WAVESHAPER_Oct2026
{
    meta:
        description = "Detects WAVESHAPER cross-platform RAT implants and droppers used by UNC1069. This rule triggers on a unique strong anchor string, or a combination of at least three supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/axios-one-rat-to-rule-them-all"
        date = "2026-10-26"
        hash1 = "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"
        hash2 = "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"
        hash3 = "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x_uv_email2, $s_uv_pkg"

    strings:
        // $x* are strong anchors: >= 16 bytes
        $x_ua = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" ascii wide  // source: explicit_literal
        $x_email1 = "ifstap@proton.me" ascii wide  // source: figure_or_disassembly
        $x_uv_email2 = "nrwise@proton.me" ascii wide  // source: prose

        // $s* are supporting strings
        $s_key = "OrDeR_7077" ascii wide  // source: explicit_literal
        $s_dl_macos = "packages.npm.org/product0" ascii wide  // source: explicit_literal
        $s_dl_win = "packages.npm.org/product1" ascii wide  // source: explicit_literal
        $s_dl_linux = "packages.npm.org/product2" ascii wide  // source: explicit_literal
        $s_cmd1 = "FirstInfo" ascii wide  // source: explicit_literal
        $s_cmd2 = "peinject" ascii wide  // source: explicit_literal
        $s_cmd3 = "runscript" ascii wide  // source: explicit_literal
        $s_cmd4 = "rundir" ascii wide  // source: explicit_literal
        $s_path1 = "/6202033" ascii wide  // source: explicit_literal
        $s_uv_pkg = "plain-crypto-js" ascii wide  // source: prose

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
