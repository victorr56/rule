# OTTERCOOKIE

Source: https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography

DPRK-aligned Contagious Interview actors target developers with fake job interviews and trojanized Next.js e-commerce take-home projects whose malicious code is hidden as Base64 fragments inside SVG flag images and reassembled via eval() on server start. The four-stage, OTTERCOOKIE-aligned payload steals browser credentials, crypto-wallet LevelDB stores, developer files and clipboard data, and installs a Socket.IO backdoor with a Windows PE dropper. All C2, upload and download activity is hosted under the rightwidth[.]dev domain family.

- **APT_ContagiousInterview_OTTERCOOKIE_Payload_Oct2026** (yara, high): The rule detects the OTTERCOOKIE JavaScript payload by keying on unique strings like the SVG Base64 comment extraction regex, custom function calls, second-stage download paths, hardcoded build paths, and multipart form boundaries for data exfiltration. A fallback condition requires a combination of several supporting indicators.
- **ContagiousInterviewOttercookieClipboardStealing** (sigma, high): This rule detects a specific process chain (`node.exe` -> `powershell.exe`) and command line (`Get-Clipboard`) used for clipboard theft by OTTERCOOKIE.
- **ContagiousInterviewOttercookieLockFile** (sigma, high): This rule detects the creation of a uniquely named lock file (`vhost.ctl`) in a specific directory (`.npm`), a strong indicator of OTTERCOOKIE's presence.
- **ContagiousInterviewOttercookieSecondStageExecution** (sigma, high): This rule detects a suspicious process lineage where `node.exe` executes PEs masquerading as system services, a key step in the OTTERCOOKIE infection chain.
