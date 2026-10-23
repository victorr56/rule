# Hive

Source: https://www.group-ib.com/blog/hive/

Hive is a Go-based Ransomware-as-a-Service (RaaS) targeting Windows, Linux, FreeBSD and VMWare ESXi. The malware employs a unique encryption process using a custom XOR scheme with a master key table and renames files with a complex extension containing recovery information. To hinder recovery, it stops numerous services and processes, deletes shadow copies, and can wipe free disk space.

- **MAL_Hive_Ransomware_Oct2026** (yara, high): The rule keys on unique hex patterns and long, distinctive substrings from Hive's service and process kill lists, which are strong indicators. The condition logic follows strict mode to prevent false positives by requiring either a strong anchor or a robust combination of weaker but specific strings.
- **Hive_Ransomware_ESXi_VM_Shutdown** (sigma, high): This rule keys on a highly specific and destructive ESXi command unique to Hive's VM shutdown procedure.
- **Hive_Ransomware_ICACLS_Access_Grant** (sigma, medium): This rule detects the specific combination of `icacls.exe` arguments used by Hive to modify file permissions pre-encryption.
