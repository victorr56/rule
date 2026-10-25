# Lazarus

Source: https://www.group-ib.com/blog/lazarus/

Lazarus Group, attributed to North Korea, conducts financial espionage and theft targeting global financial institutions. The malware suite is modular, using a three-tier C2 infrastructure with encrypted channels, and components like Server_RAT and Client_RAT for control. They leverage watering hole attacks and legitimate tools like SoftEther VPN, while employing masquerade techniques to complicate attribution.

- **Lazarus_Toolset_Process_Creation** (sigma, high): This rule detects the execution of Lazarus Group malware components by their highly specific and unique executable names.
- **Lazarus_Server_RAT_C2** (sigma, high): This rule combines the specific process name 'Server_RAT.exe' with its known C2 port '3365', making it a high-precision detection.
- **Lazarus_Backend_Listener_C2** (sigma, high): This rule combines the specific process name 'Backend_Listener.exe' with its known C2 port '9090', making it a high-precision detection.
- **Lazarus_C2_IPs** (sigma, high): This rule detects network connections to a list of IP addresses specifically identified as Lazarus Group C2 infrastructure.
