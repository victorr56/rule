# BlackNevas

Source: https://securelist.com/virtualization-security-esxi-and-proxmox-ransomware-cases/121819/

BlackNevas ransomware targets ESXi environments by gaining access via reused root credentials over SSH. Attackers use the native `esxcli` tool to disable the `execInstalledOnly` security control, then execute the ransomware binary from the command line with arguments for path, self-testing, and log wiping.

- **MAL_BlackNevas_Proxmox_Nov2026** (yara, medium): The rule keys on a unique Proxmox API path found in the malware, which is a strong indicator of compromise.
- **BlackNevas_ESXi_Disable_execInstalledOnly** (sigma, high): This rule detects the specific command line used to disable a key ESXi security feature, a direct precursor to the main payload execution.
- **BlackNevas_Ransomware_Execution** (sigma, high): This rule detects the execution of the ransomware binary 'esx' combined with its unique and destructive command-line arguments.
