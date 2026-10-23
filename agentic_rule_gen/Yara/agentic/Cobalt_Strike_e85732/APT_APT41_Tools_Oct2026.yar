/*
Self-check
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
rule APT_APT41_Tools_Oct2026
{
	meta:
		description = "Detects tools and scripts used by APT41. The rule triggers on the presence of three or more indicators, such as hardcoded passwords, specific filenames, or other unique strings."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.group-ib.com/blog/apt41-world-tour-2021/"
		date = "2026-10-23"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: the report gives no sample hash for this rule"
		score = 60
		unverified_strings = "s8"

	strings:
		$s1 = "!@#Virg0#@!" ascii wide  // source: figure_or_disassembly
		$s2 = "P$ssw0rd0006" ascii wide  // source: figure_or_disassembly
		$s3 = "Passw0rd@123" ascii wide  // source: figure_or_disassembly
		$s4 = "mciwave.exe" ascii wide  // source: figure_or_disassembly
		$s5 = "vmserver.exe" ascii wide  // source: figure_or_disassembly
		$s6 = "COMSysUpdate.exe" ascii wide  // source: figure_or_disassembly
		$s7 = "payload" ascii wide  // source: figure_or_disassembly
		$s8 = "yuming" ascii  // source: prose
		$s9 = { e8 bf 9c e6 8e a7 }  // source: figure_or_disassembly, "远控" (remote control) in UTF-8

	condition:
		uint16(0) == 0x5a4d and filesize < 10MB and
		3 of ($s*)
}
