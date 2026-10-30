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
rule MAL_Agentic_Attack_Patterns_Oct2026
{
	meta:
		description = "Detects scripts and binaries associated with agentic attacks, characterized by self-documenting comments and specific API paths. Detection is based on the presence of one strong unique string in a binary file, or a combination of multiple weaker indicators in any file type."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.wiz.io/blog/the-rise-of-agentic-attacks"
		date = "2026-10-30"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: the report gives no sample hash for this rule"
		score = 60
		unverified_strings = "x4, a1, a2, s3, s4"

	strings:
		// Strong Anchors ($x*) - highly specific comments and API paths (>= 16 chars)
		$x1 = "restart-free activation: SIGUSR1 opens the inspector" ascii // source: figure_or_disassembly
		$x2 = "Lesson from v1: target #3 had a CUSTOMIZED WHITELIST_URLS" ascii // source: figure_or_disassembly
		$x3 = "v2 switches to paths that are NOT in the whitelist, so the request actually reaches validateAPIKey" ascii // source: figure_or_disassembly
		$x4 = "But the OTHER <agent> got the 600k-row dump... how?" ascii // source: explicit_literal
		$x5 = "path test to DynamoDB with MAX OPSEC: NO deployment, NO writes" ascii // source: figure_or_disassembly
		$x6 = "invalid field to trigger a 'did you mean' suggestion" ascii // source: figure_or_disassembly
		$x7 = "/api/global-parameters/evil@" ascii // source: figure_or_disassembly
		$x8 = "/api/global-parameters/oracle@" ascii // source: figure_or_disassembly
		$x9 = "return '<MARKER>'" ascii // source: figure_or_disassembly

		// Medium-strength unique strings ($a*)
		$a1 = "k8s_ssar_all.sh" ascii // source: prose
		$a2 = "/stdio-rce-a" ascii // source: prose
		$a3 = "/result/" ascii // source: figure_or_disassembly
		
		// Supporting strings ($s*)
		$s1 = "evil@" ascii // source: figure_or_disassembly
		$s2 = "oracle@" ascii // source: figure_or_disassembly
		$s3 = "refl.py" ascii // source: prose
		$s4 = ":19001" ascii // source: prose

	condition:
		filesize < 5MB and
		(
			(1 of ($x*) and (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcffaedfe)) or
			(2 of ($a*) and 1 of ($s*)) or
			4 of ($s*)
		)
}
