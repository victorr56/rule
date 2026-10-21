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
rule MAL_Stealc_Infostealer_Oct2026
{
	meta:
		description = "Detects Stealc infostealer based on embedded command and configuration keywords. A match requires at least three such keywords."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.welivesecurity.com/en/eset-research/eset-takes-part-operation-endgame-disrupt-amadey-stealc/"
		date = "2026-10-16"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: the report gives no sample hash for this rule"
		score = 60
		unverified_strings = "s13"

	strings:
		// Supporting configuration and C&C JSON keys.
		// None are strong enough to be unique identifiers on their own.
		$s1 = "access_token" ascii wide  // source: artifact, from figure_or_disassembly
		$s2 = "self_delete" ascii wide  // source: artifact, from figure_or_disassembly
		$s3 = "take_screenshot" ascii wide  // source: artifact, from figure_or_disassembly
		$s4 = "steal_steam" ascii wide  // source: artifact, from figure_or_disassembly
		$s5 = "steal_outlook" ascii wide  // source: artifact, from figure_or_disassembly
		$s6 = "steal_foxmail" ascii wide  // source: artifact, from figure_or_disassembly
		$s7 = "steal_winscp" ascii wide  // source: artifact, from figure_or_disassembly
		$s8 = "parse_cookies" ascii wide  // source: artifact, from figure_or_disassembly
		$s9 = "parse_logins" ascii wide  // source: artifact, from figure_or_disassembly
		$s10 = "parse_history" ascii wide  // source: artifact, from figure_or_disassembly
		$s11 = "parse_webdata" ascii wide  // source: artifact, from figure_or_disassembly
		$s12 = "soft_path" ascii wide  // source: artifact, from figure_or_disassembly
		$s13 = "upload_file" ascii wide  // source: artifact, from prose

	condition:
		uint16(0) == 0x5a4d and
		filesize < 5MB and
		3 of ($s*)
}
