# OXLOADER (loader) delivering CASTLESTEALER

Source: https://www.elastic.co/security-labs/threat-command/oxloader-malware-loader-infostealer

OXLOADER is a previously undocumented Windows loader delivered through malicious Google Ads impersonating Node.js; it abuses the PE .reloc section and a new RWX .xtext section in a renamed copy of dui70.dll to stage shellcode, then bootstraps CASTLESTEALER in memory via Donut shellcode. It layers control-flow flattening, MBA/opaque predicates, self-modifying rolling-XOR decryption stubs and Adler-32 API hashing, plus anti-VM checks (WNetAddConnection2W emulation, CPU/RAM/refresh-rate thresholds) and CIS/Russian-language exclusions. Detection can key on the .reloc-resident shellcode bytes, the AFX_WM_DRAW2D clipboard-format call from the hijacked CRT initializer, the obf_xor_a1_with_a2_plus_33FDA routine and the CASTLESTEALER AES config key.

- **oxloader_masqueraded_execution** (sigma, high): This rule keys on the specific process path, filename, and command-line argument used by OXLOADER for masquerading.
- **oxloader_batch_downloader_execution** (sigma, high): This rule detects the command-line execution of the specifically named first-stage batch script used by OXLOADER.
- **oxloader_staging_via_temp_ocx** (sigma, medium): This rule detects a suspicious behavioral pattern used by OXLOADER: loading an OCX module from the user's temporary folder.
- **oxloader_powershell_download_from_storj** (sigma, high): This rule combines PowerShell execution with specific .NET classes and a URL pattern unique to the OXLOADER campaign.
- **oxloader_payload_filenames** (sigma, high): This rule detects process execution using highly specific and unusual filenames associated with OXLOADER payloads.
