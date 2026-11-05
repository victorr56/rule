# TraderTraitor

Source: https://www.reversinglabs.com/blog/binance-heist-what-we-know-and-what-rl-sees-in-tradertraitors-toolkit

TraderTraitor deploys a trojanized Terraform provider that downloads a shell script loader. This script extracts a Rust-based backdoor named FLATROOF from a fake font file, which then steals credentials and deploys a second backdoor, ROOFDECK, for command and control.

- **APT_TraderTraitor_Loader_Nov2026** (yara, high): This rule keys on a unique decryption key and specific C2 URLs found in the TraderTraitor loader script.
- **TraderTraitor_FLATROOF_Persistence_RunKey** (sigma, high): This rule detects a highly specific registry value name ('powershell-config-service') used for persistence in the HKCU\Run key.
- **TraderTraitor_Trojanized_Terraform_Provider_Execution** (sigma, high): This rule detects the execution of a process with a filename ('terraform-provider-awsbeta_v1.0.0') that is specific to the TraderTraitor malware.
- **TraderTraitor_FLATROOF_Payload_Execution** (sigma, high): This rule combines highly specific payload drop paths for Windows, macOS, and Linux with a masquerading command-line argument (--type=renderer).
- **TraderTraitor_C2_Download_DNS** (sigma, high): This rule uses a list of DNS domains that are highly specific to the TraderTraitor campaign infrastructure.
- **TraderTraitor_Linux_Persistence_Systemd** (sigma, high): This rule detects the use of systemctl to enable or start a service with the specific, non-standard name 'snap-imagent'.
- **TraderTraitor_Trojanized_Terraform_Provider_Child_Process** (sigma, medium): This rule detects a suspicious parent-child process relationship where a terraform provider spawns common shell or utility tools.
