/*
 * This rule detects the DOWNTOWN malware, part of the REF5961 intrusion set's toolset.
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
rule MAL_REF5961_DOWNTOWN_Oct2026
{
    meta:
        description = "Detects DOWNTOWN malware used by the REF5961 intrusion set. A match is based on finding at least three of several strings, including misspelled export names and debug messages, which are specific to this family."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/introducing-the-ref5961-intrusion-set"
        date = "2026-10-18"
        hash1 = "29c90ac124b898b2ff2a4897921d5f5cc251396e8176fc8d6fa475df89d9274d"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        unverified_strings = "s1"

    strings:
        $s1 = "GetPluginInfomation" ascii  // source: explicit_literal
        $s2 = "SendFileBuffer error -1 !!!" ascii wide  // source: strings_listing
        $s3 = "ScheduledDownloadTasks CODE_FILE_VIEW " ascii wide  // source: strings_listing
        $s4 = "ExplorerManagerC.dll" ascii wide  // source: strings_listing
        $s5 = "DeletePluginObject" ascii  // source: strings_listing

    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and
        3 of ($s*)
}
