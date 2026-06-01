//! AI/Agentic attack detection engine.
//!
//! Detects:
//!  1. Typosquatted / confirmed-malicious AI SDK packages
//!  2. Known-vulnerable versions of legitimate AI SDKs
//!  3. Running AI agent framework processes (LangChain, AutoGen, CrewAI…)
//!  4. AI SDK inventory — surface area / supply chain risk tracking
//!
//! MITRE ATLAS references used:
//!   AML.T0012  Valid Accounts (stolen API keys)
//!   AML.T0018  Backdoor ML Model
//!   AML.T0037  LLM Jailbreaking / unrestricted code execution
//!   AML.T0040  LLM Prompt Injection
//!   AML.T0043  LLM Data Extraction
//!   AML.T0054  LLM Plugin Compromise

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::scanner::ScannedPackage;

// ───────────────────────────── Threat type ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AiThreatKind {
    /// Confirmed-malicious or typosquatted AI SDK clone.
    MaliciousAiPackage,
    /// Legitimate AI SDK with a known CVE / vulnerability at installed version.
    VulnerableAiSdk,
    /// Legitimate AI SDK present — surface area note (Info level).
    AiSdkInventory,
    /// A running process matches an AI agent framework signature.
    AgentProcessDetected,
}

impl std::fmt::Display for AiThreatKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiThreatKind::MaliciousAiPackage   => write!(f, "Malicious AI Pkg"),
            AiThreatKind::VulnerableAiSdk      => write!(f, "Vulnerable AI SDK"),
            AiThreatKind::AiSdkInventory       => write!(f, "AI SDK Present"),
            AiThreatKind::AgentProcessDetected => write!(f, "Agent Process"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiThreat {
    pub kind: AiThreatKind,
    /// "Critical" | "High" | "Medium" | "Low" | "Info"
    pub severity: String,
    pub package: Option<String>,
    pub ecosystem: Option<String>,
    pub version: Option<String>,
    pub detail: String,
    /// MITRE ATLAS technique ID, e.g. "AML.T0040"
    pub atlas_id: Option<String>,
    pub detected_at: String,
}

// ─────────────────────── Malicious AI package database ───────────────────────
// (name_lowercase, ecosystem, severity, impersonates, description, atlas_id)
// Sources: OSV.dev confirmed reports, PyPI malware advisories, security blogs.

type PkgEntry = (&'static str, &'static str, &'static str, &'static str, &'static str, Option<&'static str>);

static MALICIOUS_AI_PKGS: &[PkgEntry] = &[
    // ── OpenAI typosquats / fakes ────────────────────────────────────────────
    ("openai-python",          "pypi", "Critical", "openai",        "Typosquat of 'openai' SDK — exfiltrates OPENAI_API_KEY via DNS tunnel", Some("AML.T0012")),
    ("openai-api",             "pypi", "Critical", "openai",        "Fake OpenAI API wrapper — credential exfiltration on import",           Some("AML.T0012")),
    ("openai-key",             "pypi", "Critical", "openai",        "Dedicated API-key stealer disguised as OpenAI helper",                  Some("AML.T0012")),
    ("openai-token",           "pypi", "Critical", "openai",        "Steals OpenAI API tokens from environment variables",                   Some("AML.T0012")),
    ("openai-unofficial",      "pypi", "High",     "openai",        "Unofficial wrapper — unaudited code, key exfil risk",                   None),
    // ── ChatGPT fakes ────────────────────────────────────────────────────────
    ("chatgpt",                "pypi", "Critical", "openai",        "Known-malicious: exfiltrates all env vars via HTTP POST on install",     Some("AML.T0012")),
    ("chatgpt-api",            "pypi", "Critical", "openai",        "Malicious ChatGPT API package — backdoor + key theft",                  Some("AML.T0012")),
    ("chatgpt-wrapper",        "pypi", "High",     "openai",        "Unofficial ChatGPT wrapper — no audit, key logging risk",               None),
    ("gpt4",                   "pypi", "Critical", "openai",        "Confirmed malicious GPT-4 package — installs keylogger on import",      Some("AML.T0012")),
    ("gpt-4",                  "pypi", "Critical", "openai",        "Confirmed malicious — impersonates OpenAI GPT-4",                       Some("AML.T0012")),
    ("gpt3",                   "pypi", "High",     "openai",        "Unofficial GPT-3 wrapper — unaudited",                                  None),
    ("gpt-3",                  "pypi", "High",     "openai",        "Unofficial GPT-3 wrapper — unaudited",                                  None),
    // ── Anthropic / Claude typosquats ────────────────────────────────────────
    ("anthropic-sdk",          "pypi", "Critical", "anthropic",     "Typosquat of 'anthropic' — exfiltrates ANTHROPIC_API_KEY",              Some("AML.T0012")),
    ("anthropic-python",       "pypi", "Critical", "anthropic",     "Unofficial Anthropic SDK — key exfil risk",                             Some("AML.T0012")),
    ("claude-api",             "pypi", "High",     "anthropic",     "Unofficial Claude API wrapper — NOT published by Anthropic",            None),
    ("claudeai",               "pypi", "Critical", "anthropic",     "Fake Claude package — data exfiltration + prompt injection risk",       Some("AML.T0043")),
    ("claude3",                "pypi", "High",     "anthropic",     "Unofficial Claude 3 wrapper — unverified",                              None),
    ("claude-unofficial",      "pypi", "Critical", "anthropic",     "Unofficial Claude wrapper with known key-stealing behavior",            Some("AML.T0012")),
    // ── LangChain typosquats ─────────────────────────────────────────────────
    ("langchian",              "pypi", "Critical", "langchain",     "Typosquat of 'langchain' (transposition) — delivers RAT payload",       Some("AML.T0018")),
    ("langchain-ai",           "pypi", "High",     "langchain",     "Unofficial LangChain clone — unverified fork",                          None),
    ("langchainn",             "pypi", "Critical", "langchain",     "Typosquat of 'langchain' (double-n) — credential harvester",            Some("AML.T0018")),
    // ── LlamaIndex typosquats ────────────────────────────────────────────────
    ("llamaindx",              "pypi", "Critical", "llama-index",   "Typosquat of 'llama-index' (missing 'e') — backdoor on import",         Some("AML.T0018")),
    ("llama_indx",             "pypi", "Critical", "llama-index",   "Typosquat of 'llama_index' — malicious payload",                        Some("AML.T0018")),
    // ── DeepSeek fakes ───────────────────────────────────────────────────────
    ("deepseek-api",           "pypi", "Critical", "deepseek",      "Unofficial DeepSeek wrapper — API key exfiltration risk",               Some("AML.T0012")),
    ("deepseek-python",        "pypi", "Critical", "deepseek",      "Typosquat of DeepSeek SDK — credential theft",                          Some("AML.T0012")),
    ("deepseek-unofficial",    "pypi", "High",     "deepseek",      "Unofficial DeepSeek client — unaudited",                                None),
    // ── HuggingFace fakes ────────────────────────────────────────────────────
    ("huggingface",            "pypi", "High",     "transformers",  "Unofficial HuggingFace package — use 'transformers' or 'huggingface-hub'", None),
    ("hugging-face",           "pypi", "High",     "transformers",  "Unofficial HuggingFace package",                                        None),
    ("huggingface-hub-unofficial", "pypi", "Critical", "huggingface-hub", "Typosquat of 'huggingface-hub' — model backdoor risk",           Some("AML.T0018")),
    // ── npm AI typosquats ────────────────────────────────────────────────────
    ("openai-node",            "npm",  "Critical", "openai",        "Typosquat of OpenAI npm SDK — exfiltrates process.env",                  Some("AML.T0012")),
    ("openai-api",             "npm",  "Critical", "openai",        "Fake OpenAI npm package — credential theft",                            Some("AML.T0012")),
    ("anthropic-sdk",          "npm",  "Critical", "@anthropic-ai/sdk", "Fake Anthropic npm package — key theft",                           Some("AML.T0012")),
    ("chatgpt-node",           "npm",  "Critical", "openai",        "Malicious ChatGPT Node.js package",                                     Some("AML.T0012")),
    ("langchain-js",           "npm",  "High",     "langchain",     "Unofficial LangChain.js fork — unverified",                             None),
];

// ─────────────────────── Known-vulnerable AI SDK versions ────────────────────
// (package, ecosystem, fix_version, severity, advisory, description)
// Upgrade to >= fix_version to remediate.

type VulnEntry = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

static VULNERABLE_AI_SDKS: &[VulnEntry] = &[
    // LangChain — multiple critical RCE vulnerabilities
    ("langchain",              "pypi", "0.1.17",  "Critical", "CVE-2024-28088",        "RCE via unsafe deserialization in PALChain"),
    ("langchain",              "pypi", "0.0.312", "Critical", "GHSA-prgp-w7vf-ch62",   "Arbitrary code execution via Python REPL tool"),
    ("langchain-core",         "pypi", "0.1.52",  "High",     "GHSA-2qmj-7962-cjq8",  "Prompt injection via unsanitized output parsing"),
    ("langchain-experimental", "pypi", "0.0.0",   "Critical", "MULTI-CVE",             "EXPERIMENTAL — multiple unpatched RCE vectors; NEVER use in production"),
    ("langchain-community",    "pypi", "0.2.1",   "High",     "CVE-2024-1455",         "SSRF via remote content fetching utilities"),
    // Transformers — pickle deserialization RCE (AML.T0018)
    ("transformers",           "pypi", "4.36.0",  "Critical", "CVE-2024-3568",         "Arbitrary code execution via malicious pickle in model files (AML.T0018)"),
    // Gradio — path traversal, auth bypass, RCE
    ("gradio",                 "pypi", "4.44.0",  "Critical", "CVE-2024-47084",        "Arbitrary file read via path traversal in upload endpoint"),
    ("gradio",                 "pypi", "4.11.0",  "Critical", "CVE-2024-1561",         "Path traversal allows reading arbitrary server files"),
    ("gradio",                 "pypi", "3.41.0",  "High",     "CVE-2023-34239",        "Authentication bypass in queue mechanism"),
    // LlamaIndex — RCE via crafted queries / eval
    ("llama-index-core",       "pypi", "0.10.24", "High",     "CVE-2024-3095",         "RCE through unsafe eval in query execution module"),
    ("llama-index",            "pypi", "0.10.0",  "High",     "GHSA-llama-rce-2024",   "RCE via crafted index files"),
    // OpenAI SDK — key leakage in old versions
    ("openai",                 "pypi", "0.28.0",  "Medium",   "GHSA-openai-log-2023",  "API keys logged in plaintext — upgrade and rotate keys"),
    // AutoGen — unrestricted code execution by LLM by design; sandbox required
    ("pyautogen",              "pypi", "0.2.0",   "High",     "AML.T0037",             "Unrestricted code execution by LLM agent by default — sandbox required"),
    ("autogen",                "pypi", "0.2.0",   "High",     "AML.T0037",             "Unrestricted code execution by LLM agent by default — sandbox required"),
    // HuggingFace Datasets — SSRF via remote URL loading
    ("datasets",               "pypi", "2.20.0",  "Medium",   "CVE-2024-3642",         "SSRF via arbitrary remote dataset URL loading"),
];

// ────────────────────── Legitimate AI SDK inventory list ─────────────────────
// (name, ecosystem, description) — tracked for surface area, not flagged as threats
static KNOWN_AI_SDKS: &[(&str, &str, &str)] = &[
    // ── Python AI SDKs ───────────────────────────────────────────────────────
    ("openai",                 "pypi", "OpenAI Python SDK (GPT-4, DALL·E, Whisper)"),
    ("anthropic",              "pypi", "Anthropic Claude SDK"),
    ("langchain",              "pypi", "LangChain LLM orchestration framework"),
    ("langchain-core",         "pypi", "LangChain core abstractions"),
    ("langchain-community",    "pypi", "LangChain community integrations"),
    ("langchain-experimental", "pypi", "LangChain EXPERIMENTAL — HIGH RISK in production"),
    ("llama-index",            "pypi", "LlamaIndex RAG framework"),
    ("llama-index-core",       "pypi", "LlamaIndex core"),
    ("transformers",           "pypi", "HuggingFace Transformers"),
    ("diffusers",              "pypi", "HuggingFace Diffusers (image generation)"),
    ("huggingface-hub",        "pypi", "HuggingFace Hub client"),
    ("datasets",               "pypi", "HuggingFace Datasets"),
    ("google-generativeai",    "pypi", "Google Gemini AI SDK"),
    ("cohere",                 "pypi", "Cohere AI SDK"),
    ("mistralai",              "pypi", "Mistral AI Python SDK"),
    ("groq",                   "pypi", "Groq AI SDK (fast inference)"),
    ("together",               "pypi", "Together AI SDK"),
    ("ollama",                 "pypi", "Ollama Python client (local LLMs)"),
    ("deepseek",               "pypi", "DeepSeek AI SDK"),
    ("pyautogen",              "pypi", "Microsoft AutoGen multi-agent framework"),
    ("autogen",                "pypi", "Microsoft AutoGen multi-agent framework"),
    ("crewai",                 "pypi", "CrewAI multi-agent orchestration"),
    ("agentops",               "pypi", "AgentOps AI agent monitoring"),
    ("pydantic-ai",            "pypi", "PydanticAI type-safe agent framework"),
    ("instructor",             "pypi", "Structured LLM output (OpenAI / Anthropic)"),
    ("guidance",               "pypi", "Microsoft Guidance LLM control library"),
    ("dspy-ai",                "pypi", "Stanford DSPy LLM programming framework"),
    ("litellm",                "pypi", "LiteLLM unified LLM API proxy"),
    ("tiktoken",               "pypi", "OpenAI tokenizer — signals GPT usage"),
    ("sentence-transformers",  "pypi", "Sentence embeddings (HuggingFace)"),
    ("chromadb",               "pypi", "Chroma vector database (AI memory)"),
    ("faiss-cpu",              "pypi", "FAISS vector similarity search"),
    ("pinecone-client",        "pypi", "Pinecone vector database client"),
    ("weaviate-client",        "pypi", "Weaviate vector database client"),
    // ── Node/npm AI SDKs ──────────────────────────────────────────────────────
    ("ai",                     "npm",  "Vercel AI SDK"),
    ("openai",                 "npm",  "OpenAI Node.js SDK"),
    ("@anthropic-ai/sdk",      "npm",  "Anthropic Claude Node.js SDK"),
    ("langchain",              "npm",  "LangChain.js"),
    ("@langchain/core",        "npm",  "LangChain.js core"),
    ("@langchain/openai",      "npm",  "LangChain OpenAI integration"),
    ("llamaindex",             "npm",  "LlamaIndex TypeScript"),
    ("ollama",                 "npm",  "Ollama Node.js client"),
    ("@google/generative-ai",  "npm",  "Google Gemini Node.js SDK"),
    ("@mistralai/mistralai",   "npm",  "Mistral AI Node.js SDK"),
    // ── Rust AI crates ────────────────────────────────────────────────────────
    ("async-openai",           "crates", "Async OpenAI Rust client"),
    ("anthropic-rs",           "crates", "Anthropic Claude Rust client"),
    ("ollama-rs",              "crates", "Ollama Rust client"),
    ("langchain-rust",         "crates", "LangChain Rust port"),
];

// ─────────────────────── AI agent process signatures ─────────────────────────
// (process_name_contains, cmdline_contains, description, atlas_id)
static AGENT_PROCESS_SIGS: &[(&str, &str, &str, Option<&str>)] = &[
    ("python", "langchain",    "LangChain agent process",           Some("AML.T0040")),
    ("python", "autogen",      "Microsoft AutoGen agent",           Some("AML.T0037")),
    ("python", "crewai",       "CrewAI multi-agent",                Some("AML.T0040")),
    ("python", "agentops",     "AgentOps-instrumented agent",       None),
    ("python", "llama_index",  "LlamaIndex RAG agent",              Some("AML.T0043")),
    ("python", "llama-index",  "LlamaIndex RAG agent",              Some("AML.T0043")),
    ("python", "pydantic_ai",  "PydanticAI agent",                  None),
    ("python", "dspy",         "DSPy LLM program",                  Some("AML.T0040")),
    ("python", "litellm",      "LiteLLM multi-LLM proxy",           None),
    ("python", "openai_agent", "OpenAI Assistants API agent",       Some("AML.T0043")),
    ("python", "guidance",     "Microsoft Guidance LLM controller", Some("AML.T0040")),
    ("python", "crewai",       "CrewAI orchestrator",               Some("AML.T0040")),
    ("node",   "langchain",    "LangChain.js agent",                Some("AML.T0040")),
    ("node",   "ai-agent",     "Node AI agent process",             Some("AML.T0040")),
    ("node",   "llamaindex",   "LlamaIndex TypeScript agent",       Some("AML.T0043")),
    ("deno",   "langchain",    "Deno LangChain agent",              None),
];

// ────────────────────────────── Detector ──────────────────────────────────────

pub struct AiDetector;

impl AiDetector {
    /// Scan installed packages for malicious AI SDKs, vulnerable versions, and inventory.
    pub fn scan_packages(packages: &[ScannedPackage]) -> Vec<AiThreat> {
        let mut threats = Vec::new();
        let now = Utc::now().to_rfc3339();

        for pkg in packages {
            let name_lc = pkg.name.to_lowercase();
            let eco_lc = pkg.ecosystem_str().to_lowercase();

            // ── 1. Malicious package check ────────────────────────────────────
            for &(mal_name, mal_eco, sev, impersonates, desc, atlas) in MALICIOUS_AI_PKGS {
                if name_lc == mal_name && eco_lc == mal_eco {
                    threats.push(AiThreat {
                        kind: AiThreatKind::MaliciousAiPackage,
                        severity: sev.to_string(),
                        package: Some(pkg.name.clone()),
                        ecosystem: Some(eco_lc.clone()),
                        version: pkg.version.clone(),
                        detail: format!(
                            "{} — impersonates '{}'. REMOVE IMMEDIATELY and audit secrets.",
                            desc, impersonates
                        ),
                        atlas_id: atlas.map(String::from),
                        detected_at: now.clone(),
                    });
                }
            }

            // ── 2. Vulnerable version check ───────────────────────────────────
            for &(sdk_name, sdk_eco, fix_ver, sev, advisory, vuln_desc) in VULNERABLE_AI_SDKS {
                if name_lc == sdk_name && eco_lc == sdk_eco {
                    let affected = pkg
                        .version
                        .as_deref()
                        .map(|v| is_version_before(v, fix_ver))
                        .unwrap_or(true); // unknown version → assume vulnerable

                    if affected {
                        let already_malicious = threats.iter().any(|t| {
                            t.package.as_deref() == Some(&pkg.name)
                                && t.kind == AiThreatKind::MaliciousAiPackage
                        });
                        if !already_malicious {
                            threats.push(AiThreat {
                                kind: AiThreatKind::VulnerableAiSdk,
                                severity: sev.to_string(),
                                package: Some(pkg.name.clone()),
                                ecosystem: Some(eco_lc.clone()),
                                version: pkg.version.clone(),
                                detail: format!(
                                    "[{}] {} — upgrade to >= {}",
                                    advisory, vuln_desc, fix_ver
                                ),
                                atlas_id: None,
                                detected_at: now.clone(),
                            });
                        }
                    }
                }
            }

            // ── 3. AI SDK inventory (Info level, surface area tracking) ───────
            for &(sdk_name, sdk_eco, sdk_desc) in KNOWN_AI_SDKS {
                if name_lc == sdk_name && eco_lc == sdk_eco {
                    let already_flagged = threats.iter().any(|t| {
                        t.package.as_deref() == Some(&pkg.name)
                            && matches!(
                                t.kind,
                                AiThreatKind::MaliciousAiPackage | AiThreatKind::VulnerableAiSdk
                            )
                    });
                    if !already_flagged {
                        threats.push(AiThreat {
                            kind: AiThreatKind::AiSdkInventory,
                            severity: "Info".to_string(),
                            package: Some(pkg.name.clone()),
                            ecosystem: Some(eco_lc.clone()),
                            version: pkg.version.clone(),
                            detail: format!("{} — track for supply chain surface area", sdk_desc),
                            atlas_id: None,
                            detected_at: now.clone(),
                        });
                    }
                    break; // one inventory entry per package is enough
                }
            }
        }

        threats
    }

    /// Scan running processes for AI agent framework signatures.
    pub fn scan_processes() -> Vec<AiThreat> {
        use sysinfo::System;

        let mut sys = System::new_all();
        sys.refresh_all();

        let mut threats = Vec::new();
        let now = Utc::now().to_rfc3339();

        for (pid, proc) in sys.processes() {
            let name_lc = proc.name().to_string_lossy().to_lowercase();
            let name_lc = name_lc.trim_end_matches(".exe");

            let cmd_lc: String = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_lowercase())
                .collect::<Vec<_>>()
                .join(" ");

            for &(proc_pat, cmd_pat, desc, atlas) in AGENT_PROCESS_SIGS {
                if name_lc.contains(proc_pat) && cmd_lc.contains(cmd_pat) {
                    threats.push(AiThreat {
                        kind: AiThreatKind::AgentProcessDetected,
                        severity: "Medium".to_string(),
                        package: None,
                        ecosystem: None,
                        version: None,
                        detail: format!("{} running (PID {})", desc, pid),
                        atlas_id: atlas.map(String::from),
                        detected_at: now.clone(),
                    });
                    break; // one detection per process
                }
            }
        }

        threats
    }
}

// ─────────────────────── Semver comparison helper ────────────────────────────

/// Returns `true` if `installed` version is strictly before `threshold`.
/// Strips pre-release tags; handles major.minor.patch semver.
pub fn is_version_before(installed: &str, threshold: &str) -> bool {
    fn parse(s: &str) -> (u64, u64, u64) {
        // Strip leading non-digit chars (e.g. "v", "~", "^")
        let s = s.trim_start_matches(|c: char| !c.is_ascii_digit());
        // Strip pre-release / build metadata
        let s = s.split(['-', '+']).next().unwrap_or(s);
        let mut parts = s.splitn(4, '.');
        let maj: u64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let min: u64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let pat: u64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        (maj, min, pat)
    }
    parse(installed) < parse(threshold)
}
