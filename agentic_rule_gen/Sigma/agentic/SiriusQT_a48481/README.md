# SiriusQT

Source: https://www.group-ib.com/blog/siriusqt-rat-hvnc-stealer/

SiriusQT is a feature-rich RAT and stealer sold as a service on dark web forums. It provides remote access, HVNC, credential theft, and keylogging capabilities using a custom encrypted C2 protocol. It is often deployed as a final stage payload via loaders like UpCrypter.

- **SiriusQT_HVNC_Browser_Launch** (sigma, high): This rule detects a highly specific command line argument used to launch a browser for HVNC, combined with common browser process names, making it a high-fidelity indicator.
- **SiriusQT_Persistence_via_UserInitMprLogonScript** (sigma, high): This rule targets a specific and uncommon persistence mechanism by monitoring writes to the `UserInitMprLogonScript` registry value, which has a very low false positive rate.
- **SiriusQT_Persistence_via_Run_Key** (sigma, medium): This rule combines the specific persistence entry name "Windows Update" in a Run key with executable paths in user-writable directories, reducing false positives from legitimate software.
- **SiriusQT_HVNC_Module_File_Drop** (sigma, high): This rule detects the specific filename of the SiriusQT HVNC module when created in common malware staging directories, providing a strong signal of compromise.
- **SiriusQT_C2_DNS_Query** (sigma, medium): This rule lists known SiriusQT C2 domains from the report for direct detection of network callbacks.
- **SiriusQT_C2_TCP_Connection** (sigma, medium): This rule lists known SiriusQT C2 IP addresses from the report, combined with specific ports where available, for direct detection of C2 communication.
