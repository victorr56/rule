# SCMBANKER

Source: https://www.elastic.co/security-labs/threat-command/mexican-banking-fraud-scmbanker-ref6045

SCMBANKER is an operator-assisted Mexican banking-fraud toolkit delivered through ClickFix fake-CAPTCHA pages that trick victims into piping a curl-fetched batch script (validation.txt) into cmd.exe from the Windows Run dialog. It sets up Run-key/Startup-folder persistence, beacons to PHP C2 panels, monitors banking window titles, captures screenshots, pushes vishing lock-screen overlays, hijacks CLABE and card-number clipboard data, and silently installs Remote Utilities for hands-on-keyboard access. All tooling is PowerShell/VBScript hosted on open directories with exposed C2 configuration editors.

- **SCMBANKER_Initial_Access_cURL_Pipe** (sigma, high): This rule detects the highly specific SCMBANKER initial access command line, combining curl, a pipe, and execution via cmd.exe.
- **SCMBANKER_Toolkit_File_Creation** (sigma, high): This rule keys on a set of highly specific SCMBANKER filenames created in the common C:\Users\Public staging directory.
- **SCMBANKER_Masquerading_Process_Execution** (sigma, high): This rule detects specific, misspelled executable names used by SCMBANKER for masquerading, which are highly unlikely to be legitimate.
- **SCMBANKER_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a list of domains exclusively associated with REF6045 SCMBANKER C2 infrastructure.
- **SCMBANKER_Decoy_Fake_Windows_Update** (sigma, medium): This rule detects the specific combination of msedge.exe, kiosk mode flags, and the fakeupdate.net domain used as a decoy by SCMBANKER.
- **SCMBANKER_Silent_Remote_Utilities_Installation** (sigma, high): This rule is precise by combining the parent process (powershell.exe), the installer (msiexec.exe), a specific filename (hosts.msi), and the silent flag.
