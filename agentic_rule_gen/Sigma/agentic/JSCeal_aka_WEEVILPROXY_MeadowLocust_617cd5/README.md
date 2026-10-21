# JSCeal (aka WEEVILPROXY, MeadowLocust)

Source: https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/

JSCeal is a cryptocurrency-focused stealer delivered as Brotli-compressed, javascript-obfuscator-protected V8 bytecode (.jsc) executed by a bundled Node.js runtime. It steals browser cookies and saved credentials, keylogs, captures screenshots, targets crypto wallets and Telegram/installed applications, and intercepts HTTPS locally through a MITM proxy with its own generated certificate. The payload is launched by a PowerShell stage via node.exe -r preflight.js app.jsc, which decompresses and loads the malware.

- **MAL_JSCeal_Stealer_Oct2026** (yara, high): This rule detects the JSCeal stealer using highly unique deobfuscated strings related to its core functionality, such as an embedded public key, specific crypto-theft queries, and custom function names.
- **JSCeal_Payload_Execution** (sigma, high): This rule detects the specific command line used by JSCeal to launch its main payload via node.exe, combining the executable name with the unique loader script `preflight.js` and payload `app.jsc`.
- **JSCeal_Crypto_Vault_Check** (sigma, medium): This rule detects a highly specific and unique URL fragment `.phantom-labs.vault.` seen in network requests made by JSCeal malware.
