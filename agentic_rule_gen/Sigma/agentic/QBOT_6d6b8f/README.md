# QBOT

Source: https://www.elastic.co/security-labs/threat-command/qbot-malware-analysis

QBOT, also known as QAKBOT, is a modular banking trojan active since at least 2007. It uses a multi-stage infection process involving regsvr32.exe for initial execution, process injection into legitimate Windows processes, and dynamic persistence via scheduled tasks and registry run keys. The malware communicates with its C2 over HTTP/TLS using a custom JSON protocol to receive commands, including downloading and executing additional modules.

- **QBot_C2_Network_Connection** (sigma, high): This rule keys on highly specific IP:Port pairs from the QBot C2 infrastructure list, providing high-confidence detections.
- **QBot_Adds_Windows_Defender_Exclusion_for_AppData** (sigma, high): This rule keys on the specific registry modification pattern QBot uses to create a Defender exclusion for its payload in AppData.
- **QBot_Injected_Process_Network_Connection** (sigma, high): This rule keys on network traffic from legitimate processes that are known QBot injection targets and normally do not make external connections.
- **QBot_Sandbox_Evasion_File_Access** (sigma, high): This rule keys on a highly specific and unusual file path that QBot checks for as part of its sandbox evasion.
- **QBot_Anti-Analysis_Tool_Enumeration** (sigma, medium): This rule keys on a command-line pattern used to enumerate running processes for specific analysis and sandboxing tools.
