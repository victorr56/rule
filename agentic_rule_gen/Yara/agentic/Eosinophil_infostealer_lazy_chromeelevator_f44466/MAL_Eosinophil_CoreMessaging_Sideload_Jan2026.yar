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
import "pe"

rule MAL_Eosinophil_CoreMessaging_Sideload_Jan2026
{
    meta:
        description = "Detects malicious CoreMessaging.dll used in Eosinophil/lazy/chromeelevator infostealer campaigns by matching unique metadata strings or export names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html"
        date = "2026-10-16"
        hash1 = "606baa263e87d32a64a9b191fc7e96ca066708b2f003bde35391908d3311a463"
        hash2 = "fd855aa20467708d004d4aab5203dd5ecdf4db2b3cb2ed7e83c27368368f02bb"
        hash3 = "a0687834ce9cb8a40b2bb30b18322298aff74147771896787609afad9016f4ea"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "$x1, $x2"

    strings:
        $x1 = "Peastaking plenipotence ductileness chilopodous codicillary." ascii wide // source: explicit_literal
        $x2 = "© 2026 Eosinophil LLC" wide // source: explicit_literal

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        (
            1 of ($x*) or
            pe.exports("15Mmm95ml1RbfjH1VUyelYFCf") or // source: figure_or_disassembly
            pe.exports("2dlSKEtPzvo1mHDN4FYgv")    // source: figure_or_disassembly
        )
}
