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
rule MAL_Tiflux_Installer_Oct2026
{
    meta:
        description = "Detects Tiflux RMM installers based on a unique hardcoded email address."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/tiflux-rmm-install"
        date = "2026-10-26"
        hash1 = "f792d82e4472c001852998a3575e492907f38daa8d58ecdb3b3604b38d7b8a07"
        hash2 = "87074c1bfd071fc47410a52af863e9ca62b2b85950c4cf643a220f0ea5717952"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "businessservices@hg.lawdepotisland.com" ascii wide // source: figure_or_disassembly

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and
        $x1
}
