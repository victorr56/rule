# Balonx Sistema (BankProtect Android RAT)

Source: https://www.group-ib.com/blog/balonx-sistema-mexico-phaas-es/

Balonx Sistema is a Mexican subscription-based Phishing-as-a-Service platform that uses a persistent WebSocket channel (SCREEN_CHANGE protocol, endpoint /ws) to relay victim input to legitimate banking portals in real time and to intercept MFA/OTP codes across 14 fake screen types. It ships an Android RAT branded BankProtect (package sacred.explosion, built on the commercial Spyroid framework) distributed via the fake PROTECCION_BANCARIA security-alert screen, plus CallFlow, an AI vishing module combining GPT-4o-mini, ElevenLabs TTS and OpenAI Whisper over a FreePBX backend. Detection can key on the RAT package/class names, base64-encoded C2 configuration fields, the /ws and /balonx paths and the CallFlow domains.

- **Balonx_Sistema_Phishing_And_C2_Domains** (sigma, high): This rule detects DNS queries for domains explicitly linked to Balonx Sistema C2 and phishing infrastructure.
- **Balonx_Sistema_C2_And_Vishing_Backend_Connection** (sigma, high): This rule detects network connections to specific IP and port pairs hardcoded in the Balonx Sistema RAT and its backend.
- **Balonx_Sistema_CallFlow_Backend_API_Access** (sigma, high): This rule detects access to specific and unique API URLs of the Balonx Sistema CallFlow backend.
- **Balonx_Sistema_PhaaS_Admin_Panel_Access** (sigma, medium): This rule detects access to the `/balonx` URI path, a unique login route for the PhaaS kit's admin panel.
