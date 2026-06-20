pub mod agent;
pub mod ares;
pub mod bootstrap;
pub mod chat;
pub mod config;
pub mod hardware;
pub mod knowledge;
pub mod model_registry;
pub mod pins;
pub mod rules;
pub mod search;

pub use agent::{
    run_agent_loop, AgentLoopConfig, AgentLoopState, AgentTick, HuntCallback, LoopStateHandle,
    OsLane, ProbeResult,
};
pub use ares::{AresAssessment, AresNeuralHunter};
pub use bootstrap::{OllamaState, DOWNLOAD_URL as OLLAMA_DOWNLOAD_URL};
pub use chat::{AresChat, ChatMessage, ChatResponse, HuntReport};
pub use config::AresConfig;
pub use hardware::{select_model, Accel, HardwareProfile, ModelSelection};
pub use knowledge::{ContextSummary, KnowledgeContext};
pub use model_registry::ModelRegistry;
pub use pins::{DigestPins, PinCheck};
pub use rules::{
    evaluate_rules, evaluate_rules_with_scope, load_rule_sets, RuleHit, RuleSet, RuntimeRuleScope,
};
pub use search::{web_search, SearchResult};
