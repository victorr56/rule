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
rule SUSP_GitHub_Pwn_Request_M_RED_TEAM_Oct2026
{
    meta:
        description = "Detects a suspicious GitHub Actions workflow configuration based on one used to compromise the AsyncAPI project. The rule requires at least four specific strings from the vulnerable workflow, which include the 'pull_request_target' trigger, checking out a pull request's head SHA, and specific job or group names."
        author = "ioc-yara-daily (agentic)"
        reference = "https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions"
        date = "2026-10-16"
        tlp = "WHITE"
        status = "untested"
        test_result = "not tested: the report gives no sample hash for this rule"
        score = 60

    strings:
        $s1 = "ref: ${{ github.event.pull_request.head.sha }}" ascii  // source: figure_literals, The vulnerable workflow
        $s2 = "pull_request_target:" ascii  // source: figure_literals, The vulnerable workflow
        $s3 = "name: Docs Preview (Netlify)" ascii  // source: figure_literals, The vulnerable workflow
        $s4 = "name: Checkout generator PR" ascii  // source: figure_literals, The vulnerable workflow
        $s5 = "group: docs-preview-${{ github.event.pull_request.number }}" ascii  // source: figure_literals, The vulnerable workflow

    condition:
        filesize < 100KB and
        4 of ($s*)
}
