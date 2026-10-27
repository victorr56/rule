# GhostChat

Source: https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/

GhostChat is an Android spyware targeting users in Pakistan, disguised as a dating app. The campaign uses a romance scam with hardcoded credentials and is linked to a broader operation involving a Windows DLL for remote code execution and a WhatsApp account hijacking scheme.

- **ghostchat_payload_download** (sigma, high): This rule detects the highly specific PowerShell command line used by the GhostChat malware to download its second-stage DLL.
- **ghostchat_payload_execution** (sigma, high): This rule detects the specific command line used to execute the GhostChat DLL via rundll32.exe, matching the DLL name and export function.
- **ghostchat_payload_drop** (sigma, medium): This rule detects the specific file name `notepad2.dll` being created in the Windows Temp directory, a behavior of the GhostChat malware.
- **ghostchat_c2_domains** (sigma, high): This rule detects DNS queries for domains known to be exclusively used by the GhostChat threat actor.
- **ghostchat_c2_beacon** (sigma, high): This rule detects a highly specific URI pattern (`/page.php?tynor=`) used for C2 beaconing by the GhostChat malware.
- **ghostchat_c2_ip** (sigma, high): This rule detects network connections to an IP address known to be exclusively used by the GhostChat threat actor.
