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
rule HKTL_Linux_Python_Memfd_Exec_Oct26
{
    meta:
        description = "Detects Python scripts using the fileless execution technique with memfd_create (syscall 319 on x86_64), as seen in the PyLoose campaign. This technique is based on the open-source 'fileless-elf-exec' tool."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/pyloose-first-python-based-fileless-attack-on-cloud-workloads"
        date = "2026-10-28"
        hash1 = "25232290fa9fa5529240a4e893ce206dfdcfc28d0b3a1b89389f7270f1046822"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
    strings:
        // Technique is based on open-source tool 'fileless-elf-exec'
        // The following strings are from the report's code snippet.
        $s1 = "syscall(319," ascii  // source: figure_or_disassembly, memfd_create on x86_64
        $s2 = "ctypes.CDLL(None)" ascii  // source: figure_or_disassembly
        $s3 = "base64.b64decode(" ascii  // source: figure_or_disassembly
        $s4 = "zlib.decompress(" ascii  // source: figure_or_disassembly
    condition:
        // Targeting text-based python scripts
        filesize < 100KB and
        3 of ($s*)
}
