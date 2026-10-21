# AVERAT, BPFDoor, Rekoobe (BPF Rekoobe)

Source: https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge

A regionalized modular access ecosystem in which a vendor-aware dropper (key derived from SHA1("ShareTech")) writes a .php shell script to a storage mount, stages AVERAT and BPFDoor/Rekoobe payloads into /sbin as ntpdate/udevds, launches them and unlinks them so /proc/<pid>/exe reads (deleted). AVERAT beacons over outbound SMTP port 25 with a hand-built TLS ClientHello and a 276-byte encrypted config, while BPFDoor and Rekoobe variants sit passive on raw PF_PACKET sockets behind classic BPF filters gated on per-sample magic bytes and passwords. Defense should focus on unlinked process images, unexpected port-25 callbacks, raw/BPF socket creation, appliance staging paths and process masquerading.

- **BPFDoor_AVERAT_Payload_Staging** (sigma, high): This rule keys on the highly specific source and destination paths used by the dropper script to stage payloads.
- **BPFDoor_AVERAT_Dropper_Script_Execution** (sigma, high): This rule keys on the specific command line used to execute the dropper script from its unusual staging location.
- **BPFDoor_Rekoobe_Masquerading_As_Appliance_Process** (sigma, high): This rule keys on a list of highly specific process paths and names used by BPFDoor/Rekoobe to masquerade.
- **AVERAT_Rekoobe_Outbound_SMTP_Traffic** (sigma, high): This rule keys on specific malware processes making outbound connections on port 25, mimicking SMTP traffic for C2.
- **BPFDoor_Kernel_Thread_Masquerade** (sigma, high): This rule keys on specific, non-standard process names designed to imitate kernel threads.
- **AVERAT_C2_Domain_Query** (sigma, medium): This rule keys on a list of known AVERAT C2 domains from the report, providing an indicator-based detection.
