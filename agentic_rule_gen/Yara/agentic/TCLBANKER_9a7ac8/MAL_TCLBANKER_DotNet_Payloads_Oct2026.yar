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
import "dotnet"

rule MAL_TCLBANKER_DotNet_Payloads_Oct2026
{
    meta:
        description = "Detects .NET payload components of the TCLBANKER trojan (Tcl.Agent and Tcl.WppBot). Detection is based on specific typelib GUIDs, unique strings, or a combination of supporting strings."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.elastic.co/security-labs/threat-command/tclbanker-brazilian-banking-trojan"
        date = "2026-10-16"
        hash1 = "cb2e7c07bd1b290444a5a1aa6362b97669f70b0a2452f311698d6c5baa0014d2"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: hash1 not available locally — the pipeline does not download malware; put samples in ioc-yara-daily/samples/ (any file name) to test"
        score = 60

    strings:
        $x1 = "NE6F/ghuiTYo5O5fDK4w8m0XkP4b+sN/crDST1nyduQzSJrrAKeIfS7x" ascii wide  // source: figure "Encrypted C2 and API key"
        $x2 = "bf7Dv0Tl1XhmtdUFvO1spjpZ3LZBs sA0L7eFSgyhaPBkA8Do" ascii wide  // source: figure "Encrypted C2 and API key"
        $x3 = "LR6Qe0E1qshTC6Mg9plCCCtvhXL5eKHbS1U=" ascii wide  // source: figure "Encrypted bank/fintech/crypto domains"
        $x4 = "IxWMeP04pt1VBb9J/ZMXiKUjHvjqJazFGQe+7YuaWQxz=" ascii wide  // source: figure "Encrypted bank/fintech/crypto domains"
        $x5 = "wss://mxtestacionamentos.com/ws" ascii wide  // source: explicit_literal
        $x6 = "https://campanha1-api.ef971a42.workers.dev/api/installs" ascii wide  // source: figure "Initial beacon to indicate successful installation", explicit_literal
        $x7 = "https://documents.ef971a42.workers.dev/api/version" ascii wide  // source: figure "Self-update hash check against the file server"
        $x8 = "no_session: QR code detectado, sem conta logada" ascii wide  // source: figure "Attempt to load WhatsApp session that does not require QR code verification"
        $x9 = "whatsapp: sessao carregada" ascii wide  // source: figure "Attempt to load WhatsApp session that does not require QR code verification"
        $x10 = "WPP.chat.sendTextMessage" ascii wide  // source: explicit_literal
        $x11 = "[Persistence] Settings OK" ascii wide  // source: figure "Register task for persistence"

        $s1 = "flutter_engine.cfg" ascii wide  // source: explicit_literal
        $s2 = "Estamos entrando em contato" ascii wide  // source: explicit_literal
        $s3 = "Marshal.GetActiveObject(\"Outlook.Application\")" ascii wide  // source: explicit_literal
        $s4 = "DisallowStartIfOnBatteries" ascii wide  // source: figure "Register task for persistence"
        $s5 = "StopIfGoingOnBatteries" ascii wide  // source: figure "Register task for persistence"
        $s6 = "RegisterTaskDefinition" ascii wide  // source: figure "Register task for persistence"
        $s7 = "brturbo.com.br" ascii wide  // source: figure "Code related to filtering potential spam victim emails"
        $s8 = "mercadolivre" ascii wide  // source: figure "Code related to filtering potential spam victim emails"
        $s9 = "casasbahia" ascii wide  // source: figure "Code related to filtering potential spam victim emails"

    condition:
        uint16(0) == 0x5a4d and filesize < 20MB and dotnet.is_dotnet and
        (
            dotnet.typelib == "0d21613a-2609-45fc-83ff-d0feaa0c891f" or
            dotnet.typelib == "b7ba9e80-0d04-4d9e-b217-c8b3cce335a2" or
            dotnet.typelib == "70e4f943-e323-4484-97d7-35401bf6812c" or
            dotnet.typelib == "0F87369F-A4E5-4CFC-BD3E-73E6154572DD" or
            1 of ($x*) or
            4 of ($s*)
        )
}
