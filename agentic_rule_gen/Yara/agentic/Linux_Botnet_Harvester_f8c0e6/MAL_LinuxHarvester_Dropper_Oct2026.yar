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
rule MAL_LinuxHarvester_Dropper_Oct2023
{
    meta:
        description = "Detects Linux ELF binaries associated with a botnet and credential harvester campaign, identified by a specific download URL."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.huntress.com/blog/codex-part-two"
        date = "2023-10-18"
        hash1 = "781c19b56fbdb17284707f9026e107f639e5447df7df3b248a5d5a50c4b0806c"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "http://162.55.234.175:4082/workersh" ascii // source: report figure_or_disassembly

    condition:
        uint32(0) == 0x464c457f and
        filesize < 1MB and
        1 of ($x*)
}
