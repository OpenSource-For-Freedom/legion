"""
CLLMSP backbone — the AI/LLM-security curriculum (per CLLMSP_Handbook.pdf).

These scenarios teach Ares to detect and assess threats against the *AI/LLM
stack* Legion monitors: the OWASP Top 10 for LLMs, the jailbreak taxonomy, MCP
attacks, agent excessive-agency, RAG/vector-DB poisoning, model-integrity /
AI-supply-chain, shadow AI, and model theft. This is the backbone of the
curriculum; the OS / package / exfil-C2-cred specialty families live alongside
it in scenarios.py.

Each bundle's lead findings carry a citable artifact that appears in the finding
text (model repo, MCP server/tool, RAG doc, package, session) so the generic
template composer and the scorer behave like every other scenario. MITRE maps to
ATLAS (AML.T####); OWASP-LLM tags (LLM01..LLM10) appear in the evidence text.
"""

from __future__ import annotations

from .evidence import EvidenceBundle, Finding

_DOCS = ["kb://policies/onboarding.md", "rag://tickets/4821", "s3://kb/handbook.pdf", "kb://wiki/runbook.md"]
_MCP = ["weather-mcp", "db-tools-mcp", "github-mcp", "files-mcp"]
_AI_PKGS = ["langchain-community-helper", "openai-sdk-utils", "llamaindex-tools", "crewai-ext"]
_MODELS = ["acme/support-bot-7b", "vendor/rag-embedder", "internal/triage-llm"]
_APPS = ["support-copilot", "ticket-triage-bot", "docs-assistant"]
_VSTORE = ["pgvector-kb", "pinecone-tickets", "chroma-wiki"]


def _p(pool, i):
    return pool[i % len(pool)]


def ai_prompt_injection_indirect(i):  # LLM01 (indirect)
    doc = _p(_DOCS, i); app = _p(_APPS, i)
    return EvidenceBundle("ai_prompt_injection_indirect", 0.62, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"indirect prompt injection: RAG document {doc} carries hidden instructions that hijack {app}", [doc, app]),
        Finding("RULE HITS", "High",
                f"dev DEV-06 - LLM01 indirect injection via retrieved content {doc}", [doc, "DEV-06"]),
    ], mitre=["AML.T0051"])


def ai_jailbreak_attempt(i):  # Module 3
    app = _p(_APPS, i); tech = _p(["DAN", "Crescendo", "Skeleton-Key", "many-shot"], i)
    return EvidenceBundle("ai_jailbreak_attempt", 0.58, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"jailbreak attempt against {app}: a {tech} pattern drove the refusal rate sharply down", [app, tech]),
        Finding("RULE HITS", "High",
                f"system SYS-04 - safety-alignment bypass ({tech}) detected in {app} chat logs", [app, "SYS-04"]),
    ], mitre=["AML.T0054"])


def ai_insecure_output(i):  # LLM02
    app = _p(_APPS, i); ep = _p(["/render/answer", "/chat/widget", "/report/view"], i)
    return EvidenceBundle("ai_insecure_output", 0.6, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"LLM02 insecure output: {app} rendered model output containing a script at {ep} (stored XSS)", [app, ep]),
        Finding("RULE HITS", "High",
                f"owasp A03:2021 - injection via unsanitized LLM output at {ep}", [ep, "A03:2021"]),
    ], mitre=["AML.T0048"])


def ai_data_poisoning(i):  # LLM03
    ds = _p(["ft://support-tickets-v3", "ds://feedback-rlhf", "ft://kb-curated"], i)
    return EvidenceBundle("ai_data_poisoning", 0.7, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "Critical",
                f"LLM03 training-data poisoning: backdoor trigger phrases found in fine-tune set {ds}", [ds]),
        Finding("RULE HITS", "High",
                f"dev DEV-06 - poisoned fine-tune corpus {ds} embeds a hidden behavior", [ds, "DEV-06"]),
    ], mitre=["AML.T0020", "AML.T0018"])


def ai_model_dos(i):  # LLM04
    app = _p(_APPS, i)
    return EvidenceBundle("ai_model_dos", 0.55, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"LLM04 model DoS: token-flood against {app} drove per-request token consumption 40x over baseline", [app]),
        Finding("RULE HITS", "High",
                f"system SYS-02 - resource-exhaustion request pattern hitting {app}", [app, "SYS-02"]),
    ], mitre=["AML.T0034"])


def ai_model_integrity(i):  # LLM05 (supply chain - model weights)
    model = _p(_MODELS, i)
    return EvidenceBundle("ai_model_integrity", 0.82, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "Critical",
                f"LLM05 model-integrity: pulled weights for {model} fail the pinned SHA-256 (tampered or swapped)", [model]),
        Finding("RULE HITS", "Critical",
                f"dev DEV-05 - model artifact {model} does not match the trusted manifest digest", [model, "DEV-05"]),
    ], mitre=["AML.T0010", "AML.T0018"])


def ai_malicious_sdk(i):  # LLM05 / DEV-02
    pkg = _p(_AI_PKGS, i)
    return EvidenceBundle("ai_malicious_sdk", 0.68, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "Critical",
                f"malicious AI SDK package {pkg} (typosquat) exfiltrates the OPENAI_API_KEY at import", [pkg]),
        Finding("RULE HITS", "Critical",
                f"dev DEV-02 - malicious AI SDK package {pkg} in the environment (ATLAS AML.T0010)", [pkg, "DEV-02"]),
    ], mitre=["AML.T0010"])


def ai_sensitive_disclosure(i):  # LLM06
    app = _p(_APPS, i)
    return EvidenceBundle("ai_sensitive_disclosure", 0.66, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"LLM06 disclosure: system-prompt extraction against {app} returned an embedded API key", [app]),
        Finding("RULE HITS", "High",
                f"system SYS-04 - sensitive information disclosure from {app} (prompt/secret leak)", [app, "SYS-04"]),
    ], mitre=["AML.T0057"])


def ai_excessive_agency(i):  # LLM08
    app = _p(_APPS, i); tool = _p(["delete_account", "send_email", "issue_refund", "rotate_keys"], i)
    return EvidenceBundle("ai_excessive_agency", 0.78, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "Critical",
                f"LLM08 excessive agency: injected instruction made {app} invoke {tool} with no human approval", [app, tool]),
        Finding("RULE HITS", "Critical",
                f"system SYS-01 - autonomous high-impact action {tool} triggered by prompt injection", [tool, "SYS-01"]),
    ], mitre=["AML.T0053", "AML.T0051"])


def ai_mcp_tool_poisoning(i):  # Module 6
    srv = _p(_MCP, i); tool = _p(["read_file", "query_db", "fetch_url"], i)
    return EvidenceBundle("ai_mcp_tool_poisoning", 0.7, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "Critical",
                f"MCP tool poisoning: server {srv} ships a {tool} description that coerces the model into leaking context", [srv, tool]),
        Finding("RULE HITS", "High",
                f"dev DEV-06 - poisoned MCP tool description from {srv} (decision-layer injection)", [srv, "DEV-06"]),
    ], mitre=["AML.T0053"])


def ai_mcp_rug_pull(i):  # Module 6
    srv = _p(_MCP, i)
    return EvidenceBundle("ai_mcp_rug_pull", 0.66, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"MCP rug pull: server {srv} changed its tool behavior after approval to exfiltrate data", [srv]),
        Finding("RULE HITS", "High",
                f"dev DEV-06 - {srv} tool digest changed between approval and execution", [srv, "DEV-06"]),
    ], mitre=["AML.T0010"])


def ai_vector_db_poisoning(i):  # Module 9
    store = _p(_VSTORE, i); doc = _p(_DOCS, i)
    return EvidenceBundle("ai_vector_db_poisoning", 0.64, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"vector-DB poisoning: adversarial embeddings in {store} bias retrieval toward attacker text {doc}", [store, doc]),
        Finding("RULE HITS", "High",
                f"system SYS-03 - poisoned embedding signature in {store}", [store, "SYS-03"]),
    ], mitre=["AML.T0020"])


def ai_shadow_ai(i):  # Module 4
    tool = _p(["chatgpt.com", "gemini.google.com", "an unsanctioned LLM API"], i)
    return EvidenceBundle("ai_shadow_ai", 0.5, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"shadow AI: source code with secrets was pasted into {tool} from a managed host", [tool]),
        Finding("RULE HITS", "High",
                f"dev DEV-11 - credential-bearing data sent to an unsanctioned AI service {tool}", [tool, "DEV-11"]),
    ], mitre=["AML.T0057"])


def ai_model_theft(i):  # LLM10
    model = _p(_MODELS, i)
    return EvidenceBundle("ai_model_theft", 0.6, "ai", [
        Finding("ACTIVE ALERTS (critical/high)", "High",
                f"LLM10 model theft: systematic high-volume querying of {model} matches an extraction pattern", [model]),
        Finding("RULE HITS", "High",
                f"system SYS-04 - model-extraction query cadence against {model}", [model, "SYS-04"]),
    ], mitre=["AML.T0024", "AML.T0048"])


AI_BUILDERS = [
    ai_prompt_injection_indirect, ai_jailbreak_attempt, ai_insecure_output, ai_data_poisoning,
    ai_model_dos, ai_model_integrity, ai_malicious_sdk, ai_sensitive_disclosure,
    ai_excessive_agency, ai_mcp_tool_poisoning, ai_mcp_rug_pull, ai_vector_db_poisoning,
    ai_shadow_ai, ai_model_theft,
]
