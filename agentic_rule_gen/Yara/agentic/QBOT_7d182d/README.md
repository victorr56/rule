# QBOT

Source: https://www.elastic.co/security-labs/blog/qbot-configuration-extractor

QBOT is a Windows malware that stores its configuration, including C2 servers, within its resources. The malware contains hardcoded strings for command-line execution, such as using 'schtasks.exe' for persistence and a unique typo 'powershel1.exe' as a configuration key.

- **MAL_QBOT_Gen_Oct2026** (yara, high): This rule keys on a long, high-entropy string found in QBOT samples, making it a strong and specific indicator.
- **QBot_Powershel1_Typo_Masquerading** (sigma, high): This rule detects a highly specific QBot executable name `powershel1.exe` which uses a typo ('1' for 'l') for masquerading, making it a critical and high-confidence indicator.
- **QBot_Schtasks_Persistence** (sigma, high): This rule detects a specific `schtasks.exe` command line used by QBot for persistence, combining the image name with a set of five distinct arguments for high precision.
- **QBot_C2_Network_Connection** (sigma, high): This rule detects network connections to a list of known QBot C2 server IP addresses extracted from malware samples.
