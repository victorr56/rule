# IcedID

Source: https://www.group-ib.com/blog/icedid/

This IcedID version uses steganography in PNG images to conceal its main module and configuration files. It establishes persistence via Scheduled Task or Run key, injects into browsers to perform MitM attacks via a local proxy, and uses basic anti-VM and anti-debugging checks. Its C2 framework includes modules for VNC, SOCKS proxy, and credential theft.

- **MAL_IcedID_Core_Oct2026** (yara, medium): Keys on multiple unique strings and artifacts, including a long fake Verisign certificate subject, a unique persistence value, and specific log messages.
- **IcedID_WMIC_AntiVirusProduct_Reconnaissance** (sigma, high): This rule detects a highly specific WMI query command line used for AV product enumeration by matching the process image with a set of distinctive arguments.
- **IcedID_Fodhelper_UAC_Bypass** (sigma, high): This rule detects a known UAC bypass technique by looking for the creation of the specific 'DelegateExecute' value with an empty data field in the 'ms-settings' registry key path.
- **IcedID_Regsvr32_Execution** (sigma, high): This rule is precise by combining the execution of `regsvr32.exe` with a command line containing the unique path segment `\lepuan\odnu\`.
- **IcedID_C2_Domains** (sigma, high): This rule detects DNS queries for a list of specific, attacker-controlled C2 domains associated with IcedID.
- **IcedID_C2_URI_Paths** (sigma, medium): This rule detects network traffic containing URI paths known to be used by IcedID for C2 communications, such as `/image/?id=`.
