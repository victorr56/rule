# NIK C2

Source: https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/

NIK C2 is a Go-based implant for Windows that integrates with the OpenAI API for on-host data analysis and generation. It uses a dual-channel C2 architecture with TLS-secured WebSockets and a fallback HTTP polling loop. Capabilities include comprehensive data theft, lateral movement, and a screen-locking ransomware module.

- **NIK_C2_Ransomware_Staging_File_Creation** (sigma, high): This rule detects the creation of highly specific filenames associated with NIK C2's ransomware module in temporary directories.
- **NIK_C2_Ransomware_Persistence_via_Run_Key** (sigma, high): This rule detects a specific persistence mechanism of the NIK C2 ransomware module by combining the use of a Run key with the specific batch file name.
- **NIK_C2_Implant_Execution_As_Simvol_exe** (sigma, medium): This rule combines a specific, though potentially arbitrary, filename with a specific command-line argument used by the NIK C2 implant.
- **NIK_C2_C2_Domain_Query** (sigma, high): This rule detects DNS queries for a domain exclusively used by NIK C2 for command and control.
