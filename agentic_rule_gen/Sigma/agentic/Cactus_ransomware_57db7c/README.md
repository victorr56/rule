# Cactus ransomware

Source: https://blog.fox-it.com/2024/04/25/sifting-through-the-spines-identifying-potential-cactus-ransomware-victims/

The Cactus ransomware group gains initial access by exploiting vulnerabilities in internet-exposed Qlik Sense servers (CVE-2023-41266, CVE-2023-41265/ZeroQlik, CVE-2023-48365/DoubleQlik) and runs discovery commands on the compromised host. Command output is redirected into True Type and WOFF font files named qle.ttf and qle.woff inside the Qlik Sense fonts directory, which are readable without authentication and serve as a reliable compromise indicator.

- **SUSP_Cactus_QlikSense_PostEx_Output_Oct2026** (yara, medium): This rule detects files containing command output from Cactus ransomware post-exploitation activity on Qlik Sense servers. The strings are highly specific PowerShell commands, directory listing headers, and full file paths found within the redirected output, making the rule precise.
- **CactusRansomwareReconnaissanceOutputFile** (sigma, high): This rule detects the creation of specific output files by common recon tools, a highly specific behavior of Cactus ransomware.
- **CactusRansomwareReconnaissanceCommandExecution** (sigma, high): This rule detects specific recon commands redirecting output to a uniquely named file path, a known Cactus ransomware TTP.
- **CactusRansomwareReconnaissanceOutputExfiltration** (sigma, high): This rule detects web requests for specific URI paths known to host Cactus ransomware's command output, a reliable indicator.
- **QlikSenseFingerprintingViaTtfBypass** (sigma, high): This rule detects a highly specific URL pattern used to exploit Qlik Sense vulnerability CVE-2023-41265.
- **LocalQlikSenseFingerprintingViaCurl** (sigma, high): This rule detects a specific local `curl` command line used by Cactus ransomware for post-exploitation fingerprinting.
