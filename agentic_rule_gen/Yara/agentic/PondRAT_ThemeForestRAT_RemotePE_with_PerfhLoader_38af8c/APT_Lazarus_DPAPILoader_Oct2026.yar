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
rule APT_Lazarus_DPAPILoader_Oct2026
{
    meta:
        description = "Detects DPAPILoader, a Windows-specific loader used by a Lazarus subgroup to decrypt and run the RemotePE RAT. Detection is based on a set of highly specific error messages, including one with a unique typo."
        author = "ioc-yara-daily (agentic)"
        reference = "https://blog.fox-it.com/2025/09/01/three-lazarus-rats-coming-for-your-cheese/"
        date = "2026-10-16"
        hash1 = "4f6ae0110cf652264293df571d66955f7109e3424a070423b5e50edc3eb43874" // DPAPILoader
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "[!] Virtual section size is out ouf bounds: " ascii wide  // source: artifact unique_string, error string with typo
        $x2 = "[!] Could not allocate memory at the desired base!\\n" ascii wide  // source: artifact unique_string, error string
        $x3 = "[!] Cannot fill imports into 32 bit PE via 64 bit loader!\\n" ascii wide  // source: artifact unique_string, error string
        $x4 = "[-] Not supported relocations format at %d: %d\\n" ascii wide  // source: artifact unique_string, error string
        $x5 = "[!] Invalid relocDir pointer\\n" ascii wide  // source: artifact unique_string, error string

    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and 1 of them
}
