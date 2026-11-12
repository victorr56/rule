# GSocket

Source: https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/

Threat actors deploy the open-source GSocket tool on compromised Linux web servers for persistent command and control. The tool uses a public relay network for stealthy, outbound-only C2, and actors employ process masquerading, various persistence methods like cron and systemd services, and file hiding to evade detection.

- **GSocket_Masquerading_With_ExecA** (sigma, high): This rule keys on the highly specific command line used to launch GSocket with a masqueraded process name.
- **GSocket_Payload_Execution_From_SHM** (sigma, high): This rule detects execution from a specific, non-standard path in shared memory, making it a high-fidelity indicator.
- **GSocket_Systemd_Persistence_DefunctService** (sigma, high): This rule detects the creation of a uniquely named systemd unit file for persistence, which is highly specific to this threat.
- **Suspicious_GSocket_Tool_Network_Activity** (sigma, medium): This rule detects network traffic to domains used by the GSocket tool, which threat actors are known to weaponize for C2.
- **GSocket_Payload_Cleanup** (sigma, medium): This rule detects the specific file deletion command used by the threat actor to cover their tracks, linking a common utility (`rm`) to a malicious path.
