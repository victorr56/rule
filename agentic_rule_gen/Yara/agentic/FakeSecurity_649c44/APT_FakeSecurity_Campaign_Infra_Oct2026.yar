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
rule APT_FakeSecurity_Campaign_Infra_Oct2026
{
	meta:
		description = "Detects malware components using C2 infrastructure associated with the FakeSecurity campaign."
		author = "ioc-yara-daily (agentic)"
		reference = "https://www.group-ib.com/blog/fakesecurity/"
		date = "2026-10-24"
		hash1 = "6ec8b7ce6c9858755964f94acdf618773275589024e2b66583e3634127b7e32c"
		hash2 = "15abc3f55703b89ff381880a10138591c6214dee7cc978b7040dd8b1e6f96297"
		hash3 = "af04334369878408898a223e63ec50e1434c512bc21d919769c97964492fee19"
		hash4 = "4587da5dca2374fd824a15e434dae6630b24d6be6916418cee48589aa6145ef6"
		hash5 = "0660059f3e2fb2ab0349242b4dde6bf9e37305dacc2da870935f4bede78aed34"
		tlp = "WHITE"
		status = "untested"
		test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
		score = 60
		unverified_strings = "x1, x2, s1, s2, s3, s4, s5"

	strings:
		// These unique paths appear in C2 URLs for Lokibot/AZORult panels.
		// They are over 16 bytes and can be considered strong anchors.
		$x1 = "/web-obtain/Panel/five/PvqDq929BSx_A_D_M1n_a.php" ascii  // source: explicit_literal
		$x2 = "/wp/Panel/five/PvqDq929BSx_A_D_M1n_a.php" ascii  // source: explicit_literal

		// Supporting strings from domains, paths, and lure filenames.
		$s1 = "umbra-diego.com" ascii  // source: explicit_literal
		$s2 = "/web-obtain/Panel/five/index.php" ascii  // source: explicit_literal
		$s3 = "alloaypparel.com/view/public/Statement00534521/PDF/Statement001854.pdf" ascii  // source: explicit_literal
		$s4 = "healthcare4all.co.uk/manuals/Statement00534521.html" ascii  // source: explicit_literal
		$s5 = "BankStatement0040918404.doc" ascii wide  // source: explicit_literal

	condition:
		uint16(0) == 0x5a4d and
		filesize < 10MB and
		(
			1 of ($x*) or
			3 of ($s*)
		)
}
