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
rule MAL_CikaBika_Loader_Oct2026
{
	meta:
		description = "Detects the Nim loader for CikaBika Bot, which uses a DLL hijacking technique against Microsoft Edge. The rule requires a combination of several path and variable name strings."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign"
		date = "2026-10-16"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: the report gives no sample hash for this rule"
		score = 60
		unverified_strings = "s4, s5"

	strings:
		$s1 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application" ascii wide  // source: figure_literals, Figure 3: Silent DLL deployer.
		$s2 = "$TargetDir\\dbghelp.dll" ascii wide  // source: figure_literals, Figure 3: Silent DLL deployer.
		$s3 = "C:\\Windows\\Temp\\dbghelp.tmp" ascii wide  // source: figure_literals, Figure 3: Silent DLL deployer.
		$s4 = "dllFile" ascii wide  // source: artifact unique_string, explicit_literal
		$s5 = "copyPs1" ascii wide  // source: artifact unique_string, explicit_literal

	condition:
		uint16(0) == 0x5a4d
		and filesize < 5MB
		and 3 of them
}
