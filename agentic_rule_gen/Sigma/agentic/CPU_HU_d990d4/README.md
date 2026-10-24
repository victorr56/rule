# CPU_HU

Source: https://www.wiz.io/blog/postgresql-cryptomining

JINX-0126 targets publicly exposed PostgreSQL servers with weak credentials to deploy a cryptominer. The malware, dubbed CPU_HU, uses a multi-stage infection with binaries like 'postmaster' and 'cpu_hu' to ultimately deploy an XMRig-C3 miner. It employs defense evasion through fileless execution, masquerading, and appending unique-per-victim configurations to its binaries.

- **Linux_CPU_HU_Masquerading_Postgres** (sigma, high): This rule detects a highly specific command line containing a homograph character (Cyrillic 'o') used by the malware to masquerade as a legitimate process.
- **Linux_CPU_HU_Postmaster_Download** (sigma, high): This rule detects a specific combination of arguments in a bash command line, characteristic of the fileless download technique used by this threat actor.
- **Linux_CPU_HU_Append_Config** (sigma, high): This rule detects a unique `printf` command line used to append a specific, large, base64-like string to the 'postmaster' payload file.
- **Linux_CPU_HU_Pg_Core_Download** (sigma, high): This rule detects the download of a specific file 'pg_core' from a unique, long URI path, covering both curl and wget usage.
- **Net_JINX-0126_C2** (sigma, high): This rule detects network traffic to a specific IP and port combination identified as a C2 server for this malware campaign.
