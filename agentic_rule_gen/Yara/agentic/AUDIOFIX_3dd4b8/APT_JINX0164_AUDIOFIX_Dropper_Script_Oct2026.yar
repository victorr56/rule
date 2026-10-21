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
rule APT_JINX0164_AUDIOFIX_Dropper_Script_Oct2026
{
    meta:
        description = "This rule detects dropper scripts used in the JINX-0164 AUDIOFIX campaign. It requires at least three indicators, such as payload URLs, typosquatted domains, or trojanized NPM package names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/threat-actors-target-crypto-orgs"
        date = "2026-10-17"
        hash1 = "9c2ce925133a3bf5a924063bbef8df49918d5b7258695c1894cd18c75970157a"
        hash2 = "c6ef82d2864dfd26f117a1ef5602679153423f2742970a7949cec72722f0a01e"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s2, s3, s4"

    strings:
        $s1 = "https://apple.driver-store.com/mac/arm/driver/coreaudiod" ascii // source: figure_or_disassembly
        $s2 = "https://apple.driver-update.io/troubleshoot/mac/audio-issue-fix.sh" ascii // source: prose
        $s3 = "windows.driver-store.com" ascii // source: prose
        $s4 = "@velora-dex/sdk" ascii // source: prose

    condition:
        filesize < 200KB and
        3 of ($s*)
}
