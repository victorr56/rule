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
rule MAL_BlackNevas_Proxmox_Nov2026
{
    meta:
        description = "Detects a component of BlackNevas ransomware targeting Proxmox environments."
        author = "ioc-yara-daily (agentic)"
        reference = "https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/"
        date = "2026-11-06"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $x1 = "/api2/json/nodes/******/vncwebsocket" ascii wide  // source: report figure_or_disassembly

    condition:
        // Covers ELF and PE
        (uint32(0) == 0x464c457f or uint16(0) == 0x5a4d) and
        filesize < 5MB and
        $x1
}
