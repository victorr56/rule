# Global Ransomware

Source: https://cofense.com/blog/from-payment-plan-to-ransomware-inside-a-global-group-attack

Global Group is a financially motivated RaaS operation, a rebrand of Black Lock and Mamona, that delivers ransomware via a fake "Suggested Payment Plan" email and PDF lure leading to an ISO with an LNK and executable. The executable spawns the legitimate WinMerge loader, which contacts globalsupportupdate.top to pull enc.exe, a Python-based encryptor that drops its toolkit into C:\Python27.x86, disables security processes, encrypts local, network-share and database data with the .nZASJgT extension and leaves README.nZASJgT.txt. Global Group operates double extortion with a Tor negotiation portal and a staged data-leak threat.

- **MAL_Global_Ransomware_Oct2026** (yara, high): This rule keys on highly specific ransom note strings, the unique onion domain, and a combination of supporting artifacts from the Global Ransomware payload.
- **GlobalRansomware_WinMerge_C2** (sigma, high): This rule detects a legitimate tool (WinMerge) connecting to known malicious domains, which is highly anomalous and specific to this threat.
- **GlobalRansomware_File_Extension** (sigma, high): The file extension `.nZASJgT` is unique to this ransomware and directly observes the impact of the attack.
- **GlobalRansomware_C2_Domains** (sigma, high): This rule lists domains that are explicitly used by the malware for payload download and C2.
- **GlobalRansomware_WinMerge_Loader_Execution** (sigma, medium): This rule detects a specific and anomalous parent-child process relationship (`Preview-9dc7.exe` -> `WinMerge.exe`) observed during malware execution.
