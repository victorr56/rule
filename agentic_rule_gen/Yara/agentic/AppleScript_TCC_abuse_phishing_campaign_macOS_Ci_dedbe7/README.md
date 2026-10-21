# AppleScript TCC-abuse phishing campaign (macOS) / CikaBika Bot

Source: https://www.darktrace.com/blog/applescript-abuse-unpacking-a-macos-phishing-campaign

A multistage macOS phishing campaign delivers AppleScript lures masquerading as Microsoft documents that exfiltrate credentials to sevrrhst[.]com and attempt to forge TCC authorizations for Apple-signed binaries before dropping a modular Node.js loader with LaunchAgent persistence. The same report documents CikaBika Bot, a Rust RAT unpacked by a Nim loader from a disk-image lure that hijacks Edge's delay-loaded dbghelp.dll and uses Discord channels plus ngrok for C2 and exfiltration. Detection anchors include the AppleScript/TCC artifacts (dscl -authonly, codesign -d --requirements, csreq, killall tccd, ~/.ex.scpt, ~/.nodes, com.appled.tcc) and the Edge dbghelp.dll plant plus Discord !shell command strings.

- **MAL_CikaBika_Bot_Oct2026** (yara, high): The rule targets the CikaBika Bot Rust RAT, using highly specific artifacts like a hardcoded Discord bot token, channel ID, and unique command-related strings found in the binary.
- **MAL_CikaBika_Loader_Oct2026** (yara, medium): This rule identifies the CikaBika loader by a combination of file paths and variable names specific to its `dbghelp.dll` hijacking routine targeting Microsoft Edge.
- **MAL_MacOS_Sevrrhst_Downloader_Oct2026** (yara, medium): This rule detects components of a macOS phishing campaign by keying on unique and lengthy C2 URLs containing the domain `sevrrhst.com`, which the report states are literal strings.
- **CikaBikaBotEdgeDbghelpSideload** (sigma, high): This rule detects the specific file path used by CikaBika for its search-order hijacking, which is a critical-level indicator.
- **CikaBikaLNKPowerShellPayload** (sigma, high): This rule detects a unique combination of keywords from the specific PowerShell command used by CikaBika to decode and run its loader.
- **AppleScriptAbuseDsclCredentialValidation** (sigma, high): This rule detects the `dscl` command with `/Search` and `-authonly` arguments, a specific technique used by the malware to validate stolen credentials.
- **AppleScriptAbuseHiddenStagedScript** (sigma, high): This rule detects the execution of the malware's specific hidden second-stage AppleScript file, `.ex.scpt`.
- **CikaBikaTempFileExecution** (sigma, high): This rule detects the specific process lineage (`powershell.exe` > `cmd.exe`) and command line used to execute the decoded CikaBika loader.
- **AppleScriptAbuseC2Domains** (sigma, high): This rule detects DNS queries for C2 domains exclusively associated with the AppleScript TCC-abuse campaign.
