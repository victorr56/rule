# XWorm

Source: https://www.malware-traffic-analysis.net/2026/09/08/index.html

A phishing email with a Spanish-language invoice lure (subject "ENVIO DOCUMENTOS FACTURA 4558") carried a RAR v5 attachment that delivered a JavaScript file which pulls down XWorm. Post-infection traffic from the infected Windows host went to TCP 43.228.157.141:7007. The infection did not survive a reboot of the host.

- **XWorm_C2_Communication** (sigma, high): This rule detects C2 traffic by keying on a specific IP address and port combination from the threat profile.
- **XWorm_JavaScript_Dropper_Execution** (sigma, high): This rule detects the malware's initial execution by combining the Windows Script Host process with a highly specific command-line argument.
