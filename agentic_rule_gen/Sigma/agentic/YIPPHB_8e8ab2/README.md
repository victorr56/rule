# YIPPHB

Source: https://www.elastic.co/security-labs/threat-command/doing-time-with-the-yipphb-dropper

YIPPHB is a dropper that follows a PowerShell loader stage. The loader uses Unicode icons embedded in Base64 strings as a simple substitution cipher to evade detection. YIPPHB is executed via InstallUtil and is used to deliver various RATs, such as NJRAT and LIMERAT.

- **MAL_YIPPHB_Loader_Oct2026** (yara, high): This rule detects the YIPPHB loader by keying on a highly unique placeholder string and a specific .NET class name found within its embedded PowerShell script.
- **MAL_YIPPHB_Dropper_Oct2026** (yara, high): This rule detects the YIPPHB dropper PE by targeting a unique, hardcoded string replacement operation used for deobfuscation, making it a very specific indicator.
- **YipphbPowerShellLoaderUnicodeObfuscation** (sigma, high): This rule detects a highly specific PowerShell obfuscation technique using the Unicode WATCH character (U+231A) as a substitution key.
- **YipphbPowerShellLoaderReversedUrl** (sigma, high): This rule keys on two highly specific reversed URL fragments found in the YIPPHB loader script block.
- **YipphbPayloadDownloadUrls** (sigma, high): This rule detects downloads from specific TinyURL and Discord CDN paths used to host YIPPHB payloads.
- **YipphbPayloadServerIp** (sigma, medium): This rule detects network connections to a list of specific IP addresses known to host YIPPHB payloads.
