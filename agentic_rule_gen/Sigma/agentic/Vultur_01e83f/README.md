# Vultur

Source: https://blog.fox-it.com/2024/03/28/android-malware-vultur-expands-its-wingspan/

Vultur is an Android banking trojan delivered by the Brunhilda dropper, a trojanised McAfee Security app that decrypts and installs three payloads (two APKs and one DEX) via native code. It abuses Android Accessibility Services and Firebase Cloud Messaging for remote control and communicates AES-encrypted, Base64-encoded JSON-RPC 2.0 over HTTPS while retaining AlphaVNC/ngrok remote access.

- **VulturC2AndDropperDomainQuery** (sigma, high): This rule detects Vultur C2 domains and a highly specific regex for dropper domains, making it a high-confidence, low-false-positive indicator of compromise.
- **VulturMalwareNgrokDownloaderURI** (sigma, high): This rule detects a specific and unusual URI pattern used by Vultur to download its ngrok component, making it a strong behavioral indicator.
- **VulturMalwareC2CommunicationViaEjrURI** (sigma, high): This rule combines the specific '/ejr/' C2 path with the 'Dalvik/' User-Agent, precisely targeting Vultur's communication from Android devices.
