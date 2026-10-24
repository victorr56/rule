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

rule MAL_Aokigahara_Stealer_Oct2026
{
    meta:
        description = "Detects Aokigahara infostealer. The rule triggers on three supporting strings, or two supporting strings if the custom PE section name '.stgcfg' is also present."
        author = "ioc-yara-daily (agentic)"
        reference = "https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/"
        date = "2026-10-24"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60
        unverified_strings = "s1, s5, s6, s7, .stgcfg"

    strings:
        // $s: Supporting strings, not unique on their own
        $s1 = "aokigahara" ascii  // source: explicit_literal
        $s2 = "kamidere" ascii  // source: strings_listing
        $s3 = "AISessions/" ascii  // source: strings_listing
        $s4 = ".ROBLOSECURITY" ascii wide  // source: strings_listing
        $s5 = "/gate/handshake" ascii  // source: explicit_literal
        $s6 = "/gate/chunk" ascii  // source: explicit_literal
        $s7 = "/gate/complete" ascii  // source: explicit_literal
        $s8 = "AKGRES" ascii  // source: strings_listing, yara_hint: short (<8 bytes) -> $s/$c only
        $s9 = "STGC" ascii  // source: figure_or_disassembly, yara_hint: short (<8 bytes) -> $s/$c only

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        (
            3 of ($s*) or
            (pe.section_index(".stgcfg") >= 0 and 2 of ($s*)) // .stgcfg source: explicit_literal
        )
}
