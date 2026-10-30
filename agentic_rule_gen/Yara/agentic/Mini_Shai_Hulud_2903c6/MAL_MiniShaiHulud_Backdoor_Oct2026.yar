import "hash"

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
rule MAL_MiniShaiHulud_Backdoor_Oct2026
{
    meta:
        description = "Detects a specific Python backdoor sample associated with the Mini-Shai-Hulud campaign based on its SHA256 hash."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/mini-shai-hulud-teampcp-hits-antv-supply-chain"
        date = "2026-10-30"
        hash1 = "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 20

    condition:
        hash.sha256(0, filesize) == "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142"
}
