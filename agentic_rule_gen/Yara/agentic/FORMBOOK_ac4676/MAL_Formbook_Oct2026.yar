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
rule MAL_Formbook_Oct2026
{
	meta:
		description = "Detects FORMBOOK malware samples based on unique byte sequences. Any one of the unique hex patterns can trigger the rule."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.elastic.co/security-labs/threat-command/formbook-adopts-cab-less-approach"
		date = "2026-10-22"
		hash1 = "bd1c1900ac1a6c7a9f52034618fed74b93acbc33332890e7d738a1d90cbc2126"
		hash2 = "4216ff4fa7533209a6e50c6f05c5216b8afb456e6a3ab6b65ed9fcbdbd275096"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: hash1, hash2 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
		score = 60
		unverified_strings = "x1, x2, x3"

	strings:
		$x1 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }  // source: explicit_literal
		$x2 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }  // source: explicit_literal
		$x3 = { 3C 30 50 4F 53 54 74 09 40 }  // source: explicit_literal

	condition:
		uint16(0) == 0x5a4d and filesize < 5MB and
		1 of ($x*)
}
