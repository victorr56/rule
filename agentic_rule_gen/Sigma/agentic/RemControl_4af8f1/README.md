# RemControl

Source: https://www.group-ib.com/blog/remcontrol-android-banking-trojan/

RemControl is an Android banking trojan distributed as a fake TVTap IPTV app dropper that suppresses Google Play Protect via a local VPN, signs its payload per installation, and abuses the Accessibility Service to inject C2-served phishing overlays, stream the screen, log keystrokes and capture lock patterns. It resolves its C2 through a Telegram dead-drop (AES-128-CBC keyed by the marker string 'numeraZZZas') and talks to a FastAPI 'RemControl Proxy' backend over WebSocket with an HTTP /api fallback. Samples are branded with the hardcoded affiliate tag UNKK and geography campaign tags such as IT-NEW and FR-NEW4.

- **UNKK_RemControl_C2_Distribution_Domains** (sigma, high): This rule detects DNS queries for domains exclusively used by RemControl for C2 and distribution.
- **UNKK_RemControl_C2_Distribution_IPs** (sigma, high): This rule detects network connections to IP addresses exclusively used by RemControl for C2 and distribution.
- **RemControl_C2_Panel_URI_Paths** (sigma, medium): This rule detects specific URI paths used for RemControl C2, data exfiltration, and panel administration.
- **RemControl_Dropper_Download** (sigma, high): This rule precisely detects the download of a RemControl payload by combining a specific hostname and URI path.
