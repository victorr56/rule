# Amadey

Source: http://nao-sec.org/2019/04/Analyzing-amadey.html

Amadey is a MinGW-compiled native Windows malware delivered by an Excel 4.0 macro document attributed to TA505, which spawns msiexec.exe to download and install the first-stage packed payload. The unpacked sample drops itself into a pseudo-random folder under ProgramData, establishes persistence through the Explorer 'User Shell Folders' Startup registry value, enumerates installed AV products, and beacons over HTTP to a hardcoded C2 using strings decrypted at runtime with a simple subtraction key.

- **Amadey_Msiexec_Downloader** (sigma, high): This rule keys on a highly specific command line for msiexec.exe containing unusual parameters used by Amadey for initial download.
- **Amadey_Persistence_Reg_Exe** (sigma, high): This rule detects the specific command line used by Amadey to create a persistence registry key, making it a high-fidelity indicator.
- **Office_Spawns_Msiexec_Downloader** (sigma, high): This rule detects a common malware delivery pattern by keying on the process lineage (Office -> msiexec) and the download action.
- **Amadey_Persistence_User_Shell_Folders** (sigma, medium): This rule detects a specific persistence mechanism by combining the modification of a known startup registry value with an unusual path.
- **Amadey_C2_Domain** (sigma, high): This rule keys on a high-confidence C2 domain specific to the Amadey malware family.
- **Amadey_C2_URI** (sigma, medium): This rule detects a specific C2 URI path observed in Amadey malware communications, providing a network-based indicator.
