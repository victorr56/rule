# EDDIESTEALER

Source: https://www.elastic.co/security-labs/threat-command/eddiestealer

EDDIESTEALER is a Rust-based infostealer distributed via fake CAPTCHA pages. It is delivered by a PowerShell command that downloads a JS loader, which in turn fetches the final payload. The stealer targets browser credentials, cryptocurrency wallets, and other sensitive data, using a configurable task list from its C2 server.

- **EddieStealer_Spawns_Invisible_Browser_Instance** (sigma, high): Keys on the highly specific '--window-position=-3000,-3000' argument used to hide a browser window off-screen.
- **EddieStealer_Enables_Chrome_Remote_Debugging** (sigma, medium): Keys on the combination of a browser process and the '--remote-debugging-port' argument, a common credential theft technique.
- **EddieStealer_Self_Deletion_via_ADS** (sigma, high): Keys on a shell process creating a file with the specific Alternate Data Stream name ':.metadata', used for self-deletion.
- **EddieStealer_C2_Domain_Query** (sigma, high): Keys on DNS queries for a list of domains known to be dedicated to EDDIESTEALER C2 infrastructure.
- **Suspicious_Access_To_FTP_Manager_Lite_Credentials** (sigma, medium): Keys on non-FTP-client processes accessing the FTP Manager Lite credential database file.
