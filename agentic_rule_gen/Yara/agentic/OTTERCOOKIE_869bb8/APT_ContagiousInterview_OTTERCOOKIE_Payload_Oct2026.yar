/*
 * Copyright (c) 2026, ioc-yara-daily (agentic)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
rule APT_ContagiousInterview_OTTERCOOKIE_Payload_Oct2026
{
    meta:
        author = "ioc-yara-daily (agentic)"
        date = "2026-10-16"
        description = "Detects the OTTERCOOKIE payload used by the DPRK-aligned Contagious Interview actor group. This rule triggers on PE files containing at least one unique indicator or three supporting strings, and on other file types (e.g., scripts) that require a higher threshold of two unique indicators or a combination of unique and supporting strings."
        reference = "https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography"
        malware_family = "OTTERCOOKIE"
        threat_actor = "Contagious Interview"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1, hash2, hash3, hash4, hash5 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60
        hash1 = "8e571d58794b9b44ae53c2c67bedef72c500e8adbb80aab7a5c263adcba55b1e"
        hash2 = "3e6360f83a95540aa2176d279ca4694513afb1e5116a7ffe591c6b5bcf3b9c3c"
        hash3 = "4e7639045b4a64de60bfb6312951a5c3dffbd3fb04b84837663242ed27f09864"
        hash4 = "54bf36910d81ab516037cb3d69d7c85190f90aa0da9e58617799c1fc738dc5a9"
        hash5 = "96357529d17c4690826d5d4c74deac51743a5388733b3f04004d898f0635ef20"
        unverified_strings = "x4, x5, x6, x7, s5, s7, s8, s9, s12"

    strings:
        // $x* strings are strong indicators; a single one can trigger on a PE file.
        $x1 = "/<!--\\\\s*([\\\\s\\\\S]*?)\\\\s*-->/" ascii  // source: figure_or_disassembly
        $x2 = "C:/tmp/ecommerce-main/assets/flags/" ascii  // source: SVG image file with Base64-encoded data
        $x3 = "C:\\\\tmp\\\\ecommerce-main\\\\assets\\\\flags\\\\" ascii  // source: SVG image file with Base64-encoded data
        $x4 = "Installing socket.io-client" ascii  // source: Network traffic showing a logging request
        $x5 = "\\\\Local Extension Settings\\\\bfnaelmomeimhlpmgjnjophhpkkoljpa\\\\ldb" ascii wide  // source: Exfiltrated cryptocurrency wallet data
        $x6 = "--------------------------ccf2f75f2a899425107e689d" ascii  // source: Exfiltrated login data via a browser stealer module
        $x7 = "--------------------------d92d2a8f9d7444e90a2135ae" ascii  // source: Network request showing text file exfiltrated

        // $s* strings are supporting indicators and require combinations to trigger.
        $s1 = "Check(validation())" ascii  // source: figure_or_disassembly
        $s2 = "/download/hostService.txt" ascii  // source: figure_or_disassembly
        $s3 = "/download/printSvc.txt" ascii  // source: figure_or_disassembly
        $s4 = "/download/dhcpSvc.txt" ascii  // source: figure_or_disassembly
        $s5 = "/api/service/makelog" ascii  // source: Network traffic showing a logging request
        $s6 = ".rightwidth.dev" ascii  // source: Multiple figures
        $s7 = "hostService.exe" ascii wide  // source: prose
        $s8 = "printSvc.exe" ascii wide  // source: prose
        $s9 = "dhcpSvc.exe" ascii wide  // source: prose
        $s10 = "while (!![])" ascii  // source: figure_or_disassembly
        $s11 = "User-Agent: axios/1." ascii  // source: Multiple figures
        $s12 = "/cldbs" ascii  // source: Exfiltrated cryptocurrency wallet data

    condition:
        filesize < 10MB and
        (
            // PE files: a lower threshold is acceptable
            uint16(0) == 0x5a4d and ( 1 of ($x*) or 3 of ($s*) )
            or
            // Non-PE (e.g., script) files: require more evidence
            ( 2 of ($x*) or (1 of ($x*) and 2 of ($s*)) )
        )
}
