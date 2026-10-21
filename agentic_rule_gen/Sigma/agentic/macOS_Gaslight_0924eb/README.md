# macOS.Gaslight

Source: https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/

macOS.Gaslight is a Rust macOS backdoor and infostealer that uses a Telegram Bot API getUpdates polling loop, AES-GCM payloads over certificate-pinned TLS, an interactive operator shell, and a com.apple.* LaunchAgent masquerade. It bundles a base64 Python stealer staged with a runtime-fetched standalone CPython interpreter and a 3.5 KB prompt-injection blob designed to derail LLM-assisted triage.

- **macos_gaslight_persistence_launchagent** (sigma, high): This rule detects the specific LaunchAgent plist filename used by macOS.Gaslight for persistence, which is highly specific to this malware.
- **macos_gaslight_c2_telegram** (sigma, high): This rule combines the specific malware executable path and filename (`system-monitoring`) with the Telegram Bot API polling URL, making it a high-fidelity C2 detection.
