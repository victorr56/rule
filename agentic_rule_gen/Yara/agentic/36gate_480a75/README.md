# 36gate

Source: https://www.group-ib.com/blog/3cx-supply-chain-attack/

A trojanized version of the 3CX Desktop App was distributed via a supply chain attack. On Windows, a malicious ffmpeg.dll loads shellcode from d3dcompiler_47.dll to download a final payload, with C2s fetched from a GitHub repository disguised as ICO files. The macOS version uses a malicious libffmpeg.dylib with hardcoded, XOR-encrypted C2 URLs.

- **APT_LabyrinthChollima_36Gate_Win_Oct2026** (yara, medium): The rule detects the Windows variant of 36Gate using a unique decryption key and event name as strong anchors, or a combination of strings specific to the trojanized 3CX application.
- **LabyrinthChollima_3CX_SideLoading_d3dcompiler_47** (sigma, high): This rule detects the core DLL side-loading behavior where the 3CX app loads a malicious `d3dcompiler_47.dll` from its own directory.
- **LabyrinthChollima_3CX_GitHub_C2_List_Retrieval** (sigma, high): This rule detects the highly specific URL pattern used to fetch C2 addresses, which is a key part of the attack chain.
- **LabyrinthChollima_3CX_macOS_C2_Cookie** (sigma, high): This rule detects a unique `Cookie` header pattern in HTTP requests, a strong behavioral indicator of the macOS implant's C2 traffic.
- **LabyrinthChollima_3CX_C2_Domains** (sigma, high): This rule detects DNS lookups for a list of known malicious C2 domains, providing a high-confidence indicator of compromise.
- **LabyrinthChollima_3CX_Downloader_Arguments** (sigma, high): This rule detects a highly specific and unusual command line used to execute the second-stage downloader, including version and User-Agent strings.
