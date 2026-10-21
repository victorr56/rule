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
rule MAL_PikaBot_Loader_Oct2026
{
    meta:
        description = "Detects the PIKABOT loader component based on specific code patterns used for API hashing. The rule requires one of two unique instruction sequences to match."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/pikabot-i-choose-you"
        date = "2026-10-18"
        hash1 = "ca5fb5814ec62c8f04936740aabe2664b3c7d036203afbd8425cd67cf1f4b79d"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = { 68 9B 8B 16 88 E8 73 FF FF FF }  // source: strings_listing, push hash(ZwQueryInformationProcess) followed by call
        $x2 = { 68 B2 CE 2E CF E8 5F FF FF FF }  // source: strings_listing, push hash(ZwCreateUserProcess) followed by call

    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        1 of ($x*)
}
