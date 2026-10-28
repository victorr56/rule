# PyLoose

Source: https://www.wiz.io/blog/pyloose-first-python-based-fileless-attack-on-cloud-workloads

PyLoose is a Python-based fileless attack targeting cloud workloads. It downloads a Python script from a paste site, which then decodes and decompresses a pre-compiled XMRig miner. The miner is loaded directly into memory using the memfd Linux feature and executed for cryptojacking.

- **HKTL_Linux_Python_Memfd_Exec_Oct26** (yara, medium): The rule detects a fileless execution technique using Python's ctypes to call the memfd_create syscall, which is attributed to an open-source tool and observed in the PyLoose campaign. The combination of strings is highly characteristic of this technique. A MAL_ rule could not be written as the only PyLoose-specific indicators were from prose.
- **Linux_PyLoose_XMRig_Wallet_ID** (sigma, high): This rule detects the unique Monero wallet ID used by the attacker, which is a critical and high-fidelity indicator of compromise found in the miner's command line.
- **Linux_PyLoose_Payload_Download** (sigma, high): This rule detects the specific `wget` command line used to download the initial payload, combining the process, the fileless execution flag `-O-`, and the unique URL.
- **Linux_PyLoose_In_Memory_Miner_Process** (sigma, high): This rule detects the execution of a process named `smd`, which is the specific name given to the in-memory XMRig process by the PyLoose malware.
- **Net_PyLoose_Mining_Pool_Connection** (sigma, high): This rule detects connections to a specific IP and port combination known to be a mining pool used by PyLoose, which is a strong indicator of compromise.
- **Proxy_PyLoose_Payload_URL** (sigma, high): This rule detects access to the exact, unique URL hosting the PyLoose malware's initial stager, making it a high-fidelity indicator.
- **DNS_PyLoose_Related_Domains** (sigma, medium): This rule detects DNS lookups for a set of domains associated with PyLoose C2 and cryptomining pools, which are anomalous in most corporate networks.
