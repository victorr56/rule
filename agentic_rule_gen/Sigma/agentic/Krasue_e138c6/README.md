# Krasue

Source: https://www.group-ib.com/blog/krasue-rat/

Krasue is a Linux Remote Access Trojan (RAT) primarily targeting telecommunications companies in Thailand. It features an embedded rootkit, based on several open-source projects, to hide its presence by hooking syscalls and hiding files, processes, and network ports. Krasue maintains persistence and communicates with its C2 server using AES-encrypted traffic over UDP and a distinctive RTSP-based 'alive ping'.

- **Krasue_RAT_RTSP_Beacon** (sigma, high): This rule keys on the unique combination of the `DESCRIBE` method and `/media.mp4` URI path used in Krasue's RTSP-based C2 beacon.
- **Krasue_RAT_Execution** (sigma, high): This rule detects the execution of the specific filename `auwd.bin`, a known indicator for the Krasue RAT.
