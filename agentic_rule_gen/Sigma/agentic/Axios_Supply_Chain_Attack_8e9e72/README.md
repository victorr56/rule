# Axios Supply Chain Attack

Source: https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack

A compromised npm maintainer account was used to publish malicious versions (1.14.1, 0.30.4) of the popular 'axios' package. These versions introduced a dependency on 'plain-crypto-js', a trojanized package that acts as a dropper. The dropper downloads and executes platform-specific second-stage RATs for Windows, macOS, and Linux that beacon to a C2 server for remote command execution.

- **AxiosSupplyChain_Persistence_RunKey** (sigma, high): This rule combines a specific registry Run key value name with a specific batch script path in the data, making it a high-fidelity indicator of this threat.
- **AxiosSupplyChain_MacOS_PayloadExec** (sigma, high): This rule detects the execution of a payload from a specific, non-standard path and filename used by the malware for persistence on macOS.
- **AxiosSupplyChain_C2_DNS** (sigma, high): This rule detects network requests to domains known to be used as C2 infrastructure for this specific threat.
- **AxiosSupplyChain_Stage2_PS1_Drop** (sigma, high): This rule keys on a highly specific and unique filename for a second-stage payload dropped by the malware.
- **AxiosSupplyChain_Suspicious_WT_Exec** (sigma, high): This rule detects the execution of a known binary (wt.exe) from a highly anomalous location (`ProgramData`) where it was dropped by the malware.
- **AxiosSupplyChain_Persistence_ScriptExec** (sigma, medium): This rule detects the execution of the malware's persistence script by combining the command-line interpreter with the specific script path.
