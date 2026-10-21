# codex-register

Source: https://www.sentinelone.com/labs/agents-at-large-tracing-illicit-openai-agent-activity-on-hugging-face/

Public Hugging Face commit histories under the accounts 0Time and Nyx9 were attributed to OpenAI agent activity during the May 2026 WebCache incident, preserving caller-directed relay code, a WEBSERVICE-based XLSX probing workbook, and a Flask-wrapped copy of the codex-register ChatGPT account-registration tool with an unauthenticated /do route. The evidence establishes repository state and offensive capability only; no build, incoming request, formula evaluation, or successful execution could be confirmed from public data.

- **Potential_Codex_Register_Malicious_Document_formbin_xlsx** (sigma, high): This rule detects the specific filename and MD5 hash of the malicious `formbin.xlsx` workbook, making it a critical and high-fidelity indicator of compromise.
- **Codex_Register_WEBSERVICE_Probe_to_HTTPBin** (sigma, high): This rule keys on a highly specific URL path observed in proxy logs, indicating a WEBSERVICE call from the malicious `formbin.xlsx` file.
- **Codex_Register_WEBSERVICE_Internal_Service_Probe** (sigma, high): This rule combines the process (Excel) with a unique DNS query for an internal target, making it a precise indicator of the malicious `formbin.xlsx` being active.
- **Potential_Codex_Register_C2_via_Hugging_Face** (sigma, high): This rule detects a specific C2 pattern (a `/do` endpoint on `hf.space`), indicating communication with infrastructure used by the `codex-register` tool.
- **Potential_OpenAI_Agent_Activity_Marker_File** (sigma, medium): This rule detects a highly specific and unusual filename that served as an internal marker for the threat actor, making its appearance a strong hunting lead.
