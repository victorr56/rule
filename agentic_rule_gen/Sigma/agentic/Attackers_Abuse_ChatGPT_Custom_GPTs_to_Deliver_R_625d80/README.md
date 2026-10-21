# Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix

Source: https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat

A ClickFix campaign that abuses attacker-created ChatGPT Custom GPTs ("Plus 5.6") and Google Sites pages to trick victims into pasting a PowerShell one-liner, which silently installs a malicious MSI (ISOSimple.msi). The MSI DLL-sideloads a patched Canon (or, in V2, Stardock) DLL that runs an encrypted loader hidden in a .wav/NuGet carrier and unpacks an encrypted virtual file system holding persistence scripts plus a full-featured RAT. Persistence is established through an HKCU Run value and a scheduled task sharing the same name, which are re-created if deleted.

- **MAL_ClickFix_RAT_Oct2026** (yara, high): This rule targets the final RAT payload of the ClickFix campaign, using highly specific strings from its configuration and functionality, as detailed in the report's string listings.
- **MAL_ClickFix_Loader_Oct2026** (yara, high): This rule detects the loader stage of ClickFix by keying on a unique import (`rdCore.dll!instance_levels_`) in the patched DLL and specific strings in the loader itself, like the name of the WAV container it processes.
- **MAL_ClickFix_Stager_Oct2026** (yara, medium): This rule detects the initial PowerShell stager of the ClickFix campaign by combining several key components of its unique, two-layer arithmetic obfuscation scheme, including static constants and deobfuscation code snippets.
- **WPS_ClickFix_Initial_Stager_Download** (sigma, high): This rule detects the initial download command, which uses a unique decimal-encoded IP (1614733393) combined with the 'irm' PowerShell cmdlet.
- **WPS_ClickFix_Persistence_RunKey** (sigma, high): This rule detects the specific Run key names and associated executable paths used by both V1 and V2 of the malware for persistence.
- **WPS_ClickFix_Sideloading_Execution** (sigma, high): This rule detects the specific process lineage where msiexec.exe launches a sideloadable binary from the actor's non-standard installation paths.
- **WPS_ClickFix_Persistence_ScheduledTask** (sigma, high): This rule detects the creation of scheduled tasks using the specific, unique names employed by the malware for persistence.
- **WPS_ClickFix_Malicious_Component_Drop** (sigma, high): This rule detects the installer process (msiexec.exe) writing uniquely named malicious DLLs to the actor's specific installation paths.
- **WPS_ClickFix_Silent_MSI_Installation** (sigma, medium): This rule detects the specific process lineage and command-line arguments used to silently install the uniquely-named malicious MSI file.
