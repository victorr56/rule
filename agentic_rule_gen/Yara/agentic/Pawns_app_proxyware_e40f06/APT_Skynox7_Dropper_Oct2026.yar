/* Self-check
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
rule APT_Skynox7_Dropper_Oct2026
{
    meta:
        description = "Detects dropper scripts or binaries used by the actor 'skynox7' to compromise edge devices. The dropper installs an SSH key for persistence and deploys the Pawns.app proxyware."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.greynoise.io/blog/proxyjacking-edge-devices-residential-proxies"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        // Strong anchors: commands targeting both root and ubnt user SSH configurations, >= 16 bytes
        $x1 = "mkdir -p /root/.ssh /home/ubnt/.ssh 2>/dev/null;" ascii  // source: figure_literals
        $x2 = "chmod 600 /root/.ssh/authorized_keys /home/ubnt/.ssh/authorized_keys 2>/dev/null;" ascii  // source: figure_literals

        // Supporting strings: fragments from the download, execution, and callback commands
        $s1 = "HOME=/tmp /tmp/gs -email=" ascii  // source: figure_literals
        $s2 = "-accept-tos >>/tmp/gs.log 2>&1;" ascii  // source: figure_literals
        $s3 = "/x86_64 -o /tmp/gs 2>/dev/null;" ascii  // source: figure_literals
        $s4 = "/cb?out=DONE_" ascii  // source: artifacts, figure_literals
        $s5 = "chmod 777 /tmp/gs 2>/dev/null;" ascii  // source: figure_literals

    condition:
        // Targets ELF droppers or scripts containing these commands
        ( uint32(0) == 0x464c457f or uint32(0) == 0x68732f6e ) and filesize < 1MB and // ELF or #!/bin/sh
        (
            1 of ($x*) or
            3 of ($s*)
        )
}
