/*
    This rule detects the JavaScript dropper component of PicassoLoader,
    used by the FrostyNeighbor actor group.
*/
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
rule APT_FrostyNeighbor_PicassoLoader_Dropper_Mar2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.welivesecurity.com/en/eset-research/frostyneighbor-fresh-mischief-digital-shenanigans/"
        date = "2026-10-16"
        description = "Detects the PicassoLoader JavaScript dropper. The condition requires at least three of several unique C2-related or persistence strings."
        malware_family = "PicassoLoader"
        threat_actor = "FrostyNeighbor"
        hash1 = "d87a4310d5718a28e8334861616c21e649ed678b871c4c81525032c58a5e3789"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $s1 = "<StartBoundary></StartBoundary>" ascii  // source: Figure 4. First-stage JavaScript dropper 53_7.03.2026_R.js
        $s2 = "book-happy.needbinding.icu" ascii  // source: figure_or_disassembly
        $s3 = "<Command>1</Command>" ascii  // source: Figure 4. First-stage JavaScript dropper 53_7.03.2026_R.js
        $s4 = "<Arguments>1</Arguments>" ascii  // source: Figure 4. First-stage JavaScript dropper 53_7.03.2026_R.js
        $s5 = "WindowsUpdate" ascii  // source: Figure 4. First-stage JavaScript dropper 53_7.03.2026_R.js
        $s6 = "UpdateService" ascii  // source: Figure 4. First-stage JavaScript dropper 53_7.03.2026_R.js

    condition:
        filesize < 1MB and
        3 of ($s*)
}
