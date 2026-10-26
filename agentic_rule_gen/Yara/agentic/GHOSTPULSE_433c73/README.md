# GHOSTPULSE

Source: https://www.elastic.co/security-labs/threat-command/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks

GHOSTPULSE is a multi-stage loader delivered via signed MSIX packages that masquerade as legitimate software installers. The loader uses PowerShell to download an encrypted payload, which is then decrypted and injected into other processes using evasion techniques like module stomping and Process Doppelgänging. The final payload is typically a known information stealer such as Lumma or Vidar.

- **MAL_GHOSTPULSE_Loader_Oct2026** (yara, low): Keys on a combination of two constants and a filename used by the GHOSTPULSE loader; confidence is low as two of the three strings are from unconfirmed sources.
- **GHOSTPULSE_PowerShell_GPG_Decryption** (sigma, high): This rule detects a highly specific PowerShell command used by GHOSTPULSE to decrypt payloads, combining a hardcoded password, gpg.exe, and specific decryption arguments.
- **GHOSTPULSE_VBoxSVC_Sideloading** (sigma, high): This rule detects the specific DLL sideloading pattern of GHOSTPULSE by matching the non-standard `VBoxSVC.exe` loading `libcurl.dll` and excluding the legitimate process path.
- **GHOSTPULSE_Payload_Filename_Handoff** (sigma, medium): This rule detects the creation of the unusually named payload file `handoff.wav` by `powershell.exe`, a specific behavior of the GHOSTPULSE loader.
- **GHOSTPULSE_Process_1msbuild_exe1** (sigma, high): This rule detects a process creation event for `1msbuild.exe1`, an extremely unusual and specific executable name used by GHOSTPULSE for process injection.
- **GHOSTPULSE_C2_Domains** (sigma, medium): This rule detects DNS queries for a known GHOSTPULSE C2 domain, which is a strong indicator of compromise.
- **GHOSTPULSE_C2_IPs** (sigma, medium): This rule detects network connections to known GHOSTPULSE C2 IP addresses, providing a strong indicator of compromise.
