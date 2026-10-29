# GopherWhisper

Source: https://www.welivesecurity.com/en/eset-research/gopherwhisper-burrow-full-malware/

GopherWhisper is a China-aligned APT group targeting Mongolian governmental entities with a custom Go-based toolset. The malware family includes backdoors like LaxGopher, RatGopher, and BoxOfFriends that use legitimate services (Slack, Discord, Outlook) for C2. A common TTP is injecting the payload, disguised as whisper.dll, into a new svchost.exe process.

- **GopherWhisper_LaxGopher_DLL_Load** (sigma, high): This rule detects a core GopherWhisper TTP by combining the specific payload DLL `whisper.dll` with the target process `svchost.exe`.
- **GopherWhisper_BoxOfFriends_Loader_DLL** (sigma, high): This rule detects the execution of the BoxOfFriends loader by its unique and specific module name, `FriendDelivery.dll`.
