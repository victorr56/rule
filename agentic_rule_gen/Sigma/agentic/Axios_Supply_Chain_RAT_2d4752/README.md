# Axios Supply-Chain RAT

Source: https://www.elastic.co/security-labs/blog/axios-supply-chain-compromise-detections

A cross-platform RAT distributed via a supply-chain attack on the Axios npm package. A malicious transitive dependency executes OS-native scripts to download and run second-stage payloads, which act as lightweight backdoors for host profiling, command execution, and persistence.

- **axios_supply_chain_windows_persistence** (sigma, high): This rule detects the specific Run key name and batch file path used by the malware for persistence.
- **axios_supply_chain_macos_payload_execution** (sigma, high): This rule keys on the highly specific and unusual full path of the macOS payload execution.
- **axios_supply_chain_linux_payload_download_exec** (sigma, high): This rule detects the specific chain of commands used to download and execute the Linux payload.
- **axios_supply_chain_windows_masquerading_powershell** (sigma, high): This rule detects a renamed PowerShell instance masquerading as `wt.exe` in a non-standard, suspicious path.
- **axios_supply_chain_macos_adhoc_codesign** (sigma, medium): This rule detects the specific command-line arguments used for ad-hoc code signing of a temporary file.
- **axios_supply_chain_c2_dns** (sigma, high): This rule detects DNS queries for a known-malicious, actor-controlled C2 domain.
