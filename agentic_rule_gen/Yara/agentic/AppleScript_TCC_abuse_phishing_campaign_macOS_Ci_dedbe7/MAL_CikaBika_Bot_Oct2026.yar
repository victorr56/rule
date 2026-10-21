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
rule MAL_CikaBika_Bot_Oct2026
{
	meta:
		description = "Detects CikaBika Bot, a Rust-based RAT using Discord for C2. The rule triggers on a unique Discord token, channel ID, or command list, or on a combination of three supporting strings."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign"
		date = "2026-10-16"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: the report gives no sample hash for this rule"
		score = 60

	strings:
		$x1 = "MTQzMjcyMjA4Mzk5NzAyODUxMg.GJpNS2.CE19P" ascii  // source: figure_literals, Figure 5: Discord configuration within the RAT.
		$x2 = "1440633973104705547" ascii  // source: figure_literals, Figure 5: Discord configuration within the RAT.
		$x3 = "Available commands: !shell, !src, !info, !download, !upload, !sysinfo, !stream, !camera, !broadcast, !isOn" ascii wide  // source: artifact unique_string, figure_or_disassembly

		$s1 = "Device is ready for manual commands" ascii wide  // source: artifact unique_string, figure_or_disassembly
		$s2 = "!tasklist" ascii wide  // source: artifact unique_string, figure_or_disassembly
		$s3 = "https://discord.com/api/v10/channels/" ascii  // source: figure_literals, Figure 5: Discord configuration within the RAT.
		$s4 = "https://cdn.discordapp.com/attachments/" ascii  // source: artifact url, figure_or_disassembly

	condition:
		uint16(0) == 0x5a4d
		and filesize < 10MB
		and (
			1 of ($x*) or
			3 of ($s*)
		)
}
