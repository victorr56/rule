# AsyncRAT

Source: https://www.darktrace.com/blog/catching-a-rat-how-darktrace-neutralized-asyncrat

AsyncRAT is an open-source Remote Access Trojan observed establishing C2 communications over non-standard TCP ports (e.g., 6606, 7707, 8808) using self-signed SSL certificates. These certificates commonly use "CN=AsyncRAT Server" for both the issuer and subject. The malware performs anti-VM checks and establishes persistence through scheduled tasks or registry modifications.

- **MAL_AsyncRAT_CN_Oct2026** (yara, high): This rule keys on the default self-signed certificate subject string "CN=AsyncRAT Server", which is highly specific to this open-source RAT and long enough to serve as a strong anchor.
- **AsyncRAT_C2_Connection_Attempt** (sigma, high): This rule keys on known C2 IPs and non-standard ports used by AsyncRAT, a high-confidence combination.
- **AsyncRAT_C2_DNS_Query** (sigma, high): This rule keys on a known C2 domain associated with AsyncRAT infrastructure.
