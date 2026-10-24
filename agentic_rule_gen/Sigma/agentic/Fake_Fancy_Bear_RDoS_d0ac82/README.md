# Fake Fancy Bear RDoS

Source: https://www.group-ib.com/blog/fakeapt28/

Financially motivated actors, masquerading as Fancy Bear, conduct Ransom DDoS (RDoS) campaigns. They send extortion emails from sednit@ctemplar.com and perform demonstrative UDP floods, notably using port 3283 (Apple Remote Desktop), to pressure victims into paying.

- **FakeFancyBear_RDoS_Network_Activity** (sigma, high): This rule detects network traffic from IPs used in Fake Fancy Bear RDoS floods, keyed on specific SourceIP-DestinationPort-Protocol combinations.
