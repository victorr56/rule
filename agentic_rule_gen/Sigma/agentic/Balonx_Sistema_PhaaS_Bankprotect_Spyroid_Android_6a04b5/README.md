# Balonx Sistema (PhaaS; Bankprotect/Spyroid Android RAT; CallFlow AI vishing)

Source: https://www.group-ib.com/blog/balonx-sistema-mexico-phaas/

Balonx Sistema is a subscription PhaaS platform targeting more than 20 Mexican financial institutions, using a persistent WebSocket (/ws) channel to push 14 fraudulent SCREEN_CHANGE screen types for real-time credential and MFA/OTP interception. It bundles an APK RAT built on Spyroid (package sacred.explosion) that beacons to a hardcoded C2 at 196.251.84.11:7771, plus a parallel AI vishing module, CallFlow, running on FreePBX at callbalonx.info. Operations rely on continuous domain rotation (350+ domains since 2019) backed by a central PostgreSQL database.

- **BalonxSistema_C2_SIP_Connection** (sigma, high): This rule detects connections to specific IP:Port pairs for the RAT C2 and SIP server, making it a high-fidelity indicator of compromise.
- **BalonxSistema_PhaaS_Domain_DNS_Query** (sigma, high): This rule detects DNS queries for a list of actor-controlled domains, which is a strong indicator of phishing or C2 activity.
- **BalonxSistema_PhaaS_API_Endpoint_Access** (sigma, high): This rule targets highly specific and long URI paths for the PhaaS backend API, making false positives extremely unlikely.
- **BalonxSistema_PhaaS_Admin_Panel_Access** (sigma, medium): This rule detects access to the specific '/balonx' admin panel path, a unique indicator for this PhaaS kit.
