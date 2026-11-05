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
rule APT_TraderTraitor_Loader_Nov2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-11-05"
        description = "Detects the TraderTraitor loader script ('safari_updater'). The rule matches on a unique hardcoded passphrase or a combination of three C2 URLs."
        reference = "https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit"
        hash1 = "451b586ec9d3c997b319986a1177829653e8ae641c953c05ede6a38616f2da97"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $s1, $s2, $s3"

    strings:
        $x1 = "PTa3WZPQZAjj55t@" ascii // source: report, explicit_literal, AES-256-CBC passphrase

        $s1 = "supportaru.serveftp.com/statics/cache/v11" ascii // source: report, explicit_literal, C2 URL
        $s2 = "raw.githubusercontent.com/bluearuhost/hospitalrun-frontend/refs/heads/main/public/fonts/version1/" ascii // source: report, explicit_literal, fallback C2 URL
        $s3 = "stage-fashion365.vercel.app/static/tinymce4.7.5/plugins/fonts/v1104" ascii // source: report, explicit_literal, fallback C2 URL

    condition:
        (
            uint32(0) == 0xfeedface or // Mach-O 32-bit
            uint32(0) == 0xfeedfacf or // Mach-O 64-bit
            uint32(0) == 0xcafebabe or // Mach-O Universal
            uint32(0) == 0xcffaedfe    // Mach-O 64-bit (reverse)
        )
        and filesize < 1MB and
        (
            $x1 or
            3 of ($s*)
        )
}
