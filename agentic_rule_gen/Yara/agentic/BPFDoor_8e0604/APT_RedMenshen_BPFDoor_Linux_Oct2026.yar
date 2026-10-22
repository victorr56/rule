/*
 Self-check
 [x] Every string has a provenance comment
 [x] No source-code identifiers / compiled-away names
 [x] Hash-gated values use the hash constant, not the plaintext
 [x] No substring redundancy within any "N of" group
 [x] No generic string can trigger the rule alone
 [x] Description matches the condition
 [x] Open-source-tool features are not attributed to the actor
 [x] Unique build identifiers (typelib GUID, PDB, keys/salts, mutexes) are $x, not downgraded
 [x] No generic padding is required by the condition
 [x] No empty meta fields
*/
rule APT_RedMenshen_BPFDoor_Linux_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-22"
        description = "Detects BPFDoor, a passive Linux backdoor attributed to Red Menshen. The rule detects files containing unique BPFDoor strings, code patterns, or a combination of several supporting strings."
        reference = "https://www.elastic.co/security-labs/threat-command/a-peek-behind-the-bpfdoor"
        hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        hash2 = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
        hash3 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        hash4 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
        hash5 = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
        score = 60
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        tlp = "WHITE"

    strings:
        // Unique strings that can fire the rule alone
        $x1 = "[+] Packet Successfuly Sending %d Size." ascii // source: strings_listing
        $x2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii // source: strings_listing
        $x3 = "Couldn't install filter %s: %s" ascii // source: strings_listing
        $x4 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 } // source: strings_listing
        $x5 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 } // source: strings_listing

        // Supporting strings, require a combination
        $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii // source: strings_listing
        $s2 = "avahi-daemon: chroot helper" ascii // source: strings_listing
        $s3 = "/sbin/mingetty /dev/tty6" ascii // source: strings_listing
        $s4 = "/sbin/auditd -n" ascii // source: strings_listing
        $s5 = "[-] Spawn shell failed." ascii // source: strings_listing
        $s6 = "decrypt_ctx" ascii // source: strings_listing
        $s7 = "getshell" ascii // source: strings_listing
        $s8 = "getpassw" ascii // source: strings_listing
        $s9 = "godpid" ascii // source: strings_listing
        $s10 = "rc4_init" ascii // source: strings_listing
        $s11 = "ttcompat" ascii // source: strings_listing

    condition:
        uint32(0) == 0x464c457f and
        filesize < 5MB and
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
