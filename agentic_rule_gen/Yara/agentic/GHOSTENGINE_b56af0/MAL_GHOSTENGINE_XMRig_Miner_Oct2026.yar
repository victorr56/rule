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
rule MAL_GHOSTENGINE_XMRig_Miner_Oct2026
{
    meta:
        description = "Detects the specific XMRig miner configuration used by GHOSTENGINE, identified by its unique Monero wallet ID."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/invisible-miners-unveiling-ghostengine"
        date = "2026-10-18"
        hash1 = "35eb368c14ad25e3b1c58579ebaeae71bdd8ef7f9ccecfc00474aa066b32a03f"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "468ED2Qcchk4shLbD8bhbC3qz2GFXqjAUWPY3VGbmSM2jfJw8JpSDDXP5xpkMAHG98FHLmgvSM6ZfUqa9gvArUWP59tEd3f" ascii  // source: report figure_or_disassembly, GHOSTENGINE XMRig Config

    condition:
        uint16(0) == 0x5a4d and filesize < 10MB and
        $x1
}
