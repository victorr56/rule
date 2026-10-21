# Rogue ScreenConnect VBScript loader (WindowsServiceHost)

Source: https://www.huntress.com/blog/rogue-screenconnect-installations

Rogue, modified ScreenConnect clients spawn wscript.exe to execute a four-stage VBScript chain (1.vbs-4.vbs) that profiles the host, downloads AES-encrypted payload bundles from Dropbox, and persists via a WindowsServiceHost Run key pointing to WindowsServiceHost.vbs. The backdoored client registers the same VBS stagers into a ScreenConnect file-transfer message with its action set to Run, propagating the chain worm-like to every newly connected Host session. Huntress ties the activity to C2 infrastructure 45.13.237[.]190 / tele-sync.opik[.]net and secondary RMM tools such as UltraViewer.

- **MAL_RogueScreenConnect_Propagation_Component_Oct2026** (yara, medium): This rule detects the backdoored ScreenConnect client by targeting a unique hardcoded file path or a combination of specific .NET type, method, and property names used in its propagation logic.
- **RogueScreenConnect_Persistence_RunKey** (sigma, high): This rule detects the specific Run key name and VBScript filename used for persistence, making it highly precise.
- **RogueScreenConnect_VBScript_Stager_Execution** (sigma, high): This rule correlates the specific parent `ScreenConnect.WindowsClient.exe` with `wscript.exe` execution from known temporary paths, a highly suspicious behavior.
- **RogueScreenConnect_C2_Domains** (sigma, high): This rule detects queries to domains exclusively associated with the threat actor's C2 infrastructure.
- **RogueScreenConnect_Payload_Archive_Creation** (sigma, high): This rule detects a file drop to a highly specific and unusual path and filename, making it a reliable indicator of compromise.
- **RogueScreenConnect_Persistence_Batch_Execution** (sigma, high): This rule detects the execution of a specifically named batch file (`WindowsServiceHost.bat`) by the VBScript interpreter, a key part of the persistence chain.
- **RogueScreenConnect_C2_IP_Connections** (sigma, high): This rule detects connections to IP addresses exclusively associated with the threat actor's C2 infrastructure.
