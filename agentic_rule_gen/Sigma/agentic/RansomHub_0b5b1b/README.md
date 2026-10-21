# RansomHub

Source: https://www.darktrace.com/blog/ransomhub-revisited-new-front-runner-in-the-ransomware-as-a-service-marketplace

RansomHub is a Go-based Ransomware-as-a-Service (RaaS) platform targeting Windows and Linux systems. Affiliates use double extortion tactics, leveraging legitimate remote access tools like Atera and Splashtop for C2 and exfiltration. Encrypted files are appended with a 6-digit alphanumeric extension, such as .293ac3.

- **RansomHubExecutionWithSecretServerSecretStealerScript** (sigma, high): This rule keys on the specific and unique PowerShell script name 'SecretServerSecretStealer' executed by powershell.exe.
- **RansomHubC2NetworkConnection** (sigma, high): This rule keys on a specific C2 IP address and destination port combination associated with RansomHub data exfiltration.
