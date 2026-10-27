/*
Self-check
[x] Every string has a provenance comment
[x] No source-code identifiers / compiled-away names
[x] Hash-gated values use the hash constant, not the plaintext
[x] No substring redundancy within any "N of" group
[x] No generic string can trigger the rule alone
[x] Description matches the condition
[x] Open-source-tool features are not attributed to the actor
[x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $s, not downgraded
[x] No generic padding is required by the condition
[x] No empty meta fields
*/
import "pe"

rule MAL_BLISTER_Loader_Oct2026 {
   meta:
      description = "Detects BLISTER loader DLLs based on a characteristic string found in its code-signing certificate subject."
      author = "ioc-yara-daily (agentic)"
      reference = "https://www.elastic.co/security-labs/threat-command/elastic-security-uncovers-blister-malware-campaign"
      date = "2026-10-27"
      hash1 = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
      hash2 = "df8142e5cf897af65972041024ebe74c7915df0e18c6364c5fb9b2943426ed1a"
      hash3 = "afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2"
      hash4 = "a34821b50aadee0dd85c382c43f44dae1e5fef0febf2f7aed6abf3f3e21f7994"
      hash5 = "8ae2c205220c95f0f7e1f67030a9027822cc18e941b669e2a52a5dbb5af74bc9"
      tlp = "WHITE"
      status = "untested"
      test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
      score = 60
      unverified_strings = "x1"
   strings:
      $s1 = "Blist LLC" ascii wide  // source: prose for artifact 'certificate_subject'

   condition:
      uint16(0) == 0x5a4d and filesize < 10MB and
      pe.is_dll() and
      1 of ($s*)
}
