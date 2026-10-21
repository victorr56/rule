/*
 * This rule detects the PHANTOMPULSE RAT used by DPRK-aligned actor REF6598.
 *
 * Self-check
 * [x] Every string has a provenance comment
 * [x] No source-code identifiers / compiled-away names
 * [x] Hash-gated values use the hash constant, not the plaintext
 * [x] No substring redundancy within any "N of" group
 * [x] No generic string can trigger the rule alone
 * [x] Description matches the condition
 * [x] Open-source-tool features are not attributed to the actor
 * [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
 * [x] No generic padding is required by the condition
 * [x] No empty meta fields
 */
rule APT_PHANTOMPULSE_RAT_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole"
        date = "2026-10-16"
        description = "Detects the PHANTOMPULSE RAT based on unique debug strings and a cluster of DJB2 hash constants. A match can be triggered by one of several unique debug strings, or by the presence of four or more command dispatch hash constants."
        hash1 = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "x1, x2, x3, x4, x5, c1"

    strings:
        // Unique and long debug/format strings, strong anchors
        $x1 = "[STEP 1/3] Scheduled Task (DotNetSvcUpdateTask, logon + every 3 min)" ascii wide  // source: explicit_literal
        $x2 = "FindHostProcessEx: scan stats: total=%lu sessSkip=%lu openFail=%lu native=%lu wow64=%lu mapReject=%lu dbgReject=%lu sess=%lu" ascii wide  // source: explicit_literal
        $x3 = "PE32 DLL in x64 host is impossible" ascii wide  // source: explicit_literal
        $x4 = "DbgNexumLoop64: stage 6 -> stub at %llx, base=%llx" ascii wide  // source: explicit_literal
        $x5 = "[UNINSTALL 4/6] Removing persist_loader DLL + registry PE data..." ascii wide  // source: explicit_literal
        $x6 = "Screenshot: failed to resolve GDI APIs" ascii wide  // source: figure_literals, Screenshot function

        // Constants: XOR key and DJB2 hashes of commands
        $c1 = { 37 A2 5C E9 }  // source: explicit_literal, Seed XOR key 0xE95CA237, little-endian
        $c2 = { 42 11 CF 04 }  // source: hash_gated, DJB2("inject"), little-endian
        $c3 = { 1A D9 95 7C }  // source: hash_gated, DJB2("drop"), little-endian
        $c4 = { 83 F0 37 9A }  // source: hash_gated, DJB2("screenshot"), little-endian
        $c5 = { F0 DE DE 08 }  // source: hash_gated, DJB2("keylog"), little-endian
        $c6 = { FF 51 E2 4E }  // source: hash_gated, DJB2("uninstall"), little-endian
        $c7 = { 0B C5 CC 65 }  // source: hash_gated, DJB2("elevate"), little-endian
        $c8 = { 80 B8 B5 B3 }  // source: hash_gated, DJB2("downgrade"), little-endian
        $c9 = { C8 3B CE 20 }  // source: hash_gated, DJB2 for self-restart, little-endian
        $c10 = { 16 5B 82 05 }  // source: hash_gated, DJB2("WDAGUtilityAccount"), computed, little-endian

    condition:
        uint16(0) == 0x5a4d and
        filesize < 20MB and
        (
            1 of ($x*) or
            4 of ($c*)
        )
}
