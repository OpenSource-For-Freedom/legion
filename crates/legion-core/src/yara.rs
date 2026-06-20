//! Pure-Rust YARA-compatible rule engine.
//!
//! This is a dependency-free implementation of a practical subset of the YARA
//! rule language, chosen so the engine builds identically on every Legion
//! target (musl-static Linux, MSVC Windows) without any C
//! library or large dependency tree.
//!
//! ## Supported subset
//! * `rule NAME : tag1 tag2 { meta: … strings: … condition: … }`
//! * Text strings — `$a = "literal"` with `nocase`, `wide`, `ascii`, `fullword`
//!   modifiers (other modifiers are accepted and ignored).
//! * Hex strings — `$a = { 4D 5A ?? 9? [2-4] AB }` with full/nibble wildcards
//!   and jumps (`[n]`, `[n-m]`, `[n-]`).
//! * Conditions — `true`/`false`, `$a`, `#a <op> N`, `filesize <op> N[KB|MB|GB]`,
//!   `N of them`, `any/all of ($a, $b*)`, grouped with `( )` and combined with
//!   `not` / `and` / `or`.
//!
//! Rules that use constructs outside this subset (regex bodies, modules such as
//! `pe.`, `for` loops, `at`/`in` offsets) are skipped with a warning rather than
//! aborting the whole compile, so a single advanced rule in a remote feed never
//! disables the rest of the set.
//!
//! ## Layout
//! * [`YaraConfig`] / [`YaraManager`] — per-OS rule selection, dynamic update
//!   from the GitHub-hosted rules repo, and on-disk caching.
//! * [`YaraEngine`] — compiled rules + scanning of bytes / files / directories.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ───────────────────────────── Bundled defaults ─────────────────────────────

const BUNDLED_CONFIG: &str = include_str!("../yara_config.json");
const BUNDLED_COMMON: &str = include_str!("../rules/common.yar");
const BUNDLED_LINUX: &str = include_str!("../rules/linux.yar");
const BUNDLED_WINDOWS: &str = include_str!("../rules/windows.yar");

/// Bundled rule text for a given rule-file name, used when no cached copy exists.
fn bundled_rule(file: &str) -> Option<&'static str> {
    match file {
        "common.yar" => Some(BUNDLED_COMMON),
        "linux.yar" => Some(BUNDLED_LINUX),
        "windows.yar" => Some(BUNDLED_WINDOWS),
        _ => None,
    }
}

/// The OS key used in [`YaraConfig::os`]: `"linux"` or `"windows"`.
pub fn current_os() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "linux"
    }
}

// ───────────────────────────────── Match ────────────────────────────────────

/// A single rule hit produced by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub tags: Vec<String>,
    /// `severity` meta value if present, else derived ("Medium").
    pub severity: String,
    /// `description`/`desc` meta value if present.
    pub description: String,
    /// File path or logical label that was scanned.
    pub target: String,
    /// String identifiers that matched (e.g. `$a`).
    pub matched_strings: Vec<String>,
    pub detected_at: String,
}

// ──────────────────────────────── Config ────────────────────────────────────

fn default_max_mb() -> u64 {
    16
}
fn default_max_files() -> usize {
    5000
}
fn default_scan_all_drives() -> bool {
    true
}
/// File-count floor for a whole-system scan: a tiny configured cap would defeat
/// "scan every drive", so all-drive scans raise the ceiling to this minimum.
const ALL_DRIVES_MIN_FILES: usize = 200_000;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OsRules {
    #[serde(default)]
    pub rule_files: Vec<String>,
    #[serde(default)]
    pub scan_paths: Vec<String>,
}

/// Parsed `yara_config.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct YaraConfig {
    #[serde(default = "default_max_mb")]
    pub max_file_size_mb: u64,
    #[serde(default = "default_max_files")]
    pub max_files_per_scan: usize,
    /// When true (default), scans cover every fixed drive / mount point on the
    /// host instead of only the per-OS `scan_paths`. See [`crate::fsroots`].
    #[serde(default = "default_scan_all_drives")]
    pub scan_all_drives: bool,
    #[serde(default)]
    pub rules_repo: String,
    #[serde(default)]
    pub os: BTreeMap<String, OsRules>,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self::bundled()
    }
}

impl YaraConfig {
    /// The configuration compiled into the binary.
    pub fn bundled() -> Self {
        serde_json::from_str(BUNDLED_CONFIG).expect("bundled yara_config.json is valid")
    }

    /// Rule set for the running OS (falls back to an empty set).
    pub fn os_rules(&self) -> OsRules {
        self.os.get(current_os()).cloned().unwrap_or_default()
    }

    pub fn max_file_size_bytes(&self) -> usize {
        (self.max_file_size_mb as usize).saturating_mul(1024 * 1024)
    }

    /// File-count cap to apply this scan. A whole-system scan raises the cap to
    /// [`ALL_DRIVES_MIN_FILES`] so a small configured value can't quietly stop a
    /// full-drive walk after a few thousand files.
    pub fn effective_max_files(&self) -> usize {
        if self.scan_all_drives {
            self.max_files_per_scan.max(ALL_DRIVES_MIN_FILES)
        } else {
            self.max_files_per_scan
        }
    }
}

// ──────────────────────────────── Manager ───────────────────────────────────

/// Outcome of a dynamic rule update.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateReport {
    pub fetched: usize,
    pub failed: usize,
    pub files: Vec<String>,
    pub errors: Vec<String>,
}

/// Owns the configuration and resolves rule text from cache → bundled fallback.
pub struct YaraManager {
    pub config: YaraConfig,
    data_dir: PathBuf,
}

impl YaraManager {
    /// Load the manager, preferring `<data_dir>/yara_config.json` over the
    /// bundled config. On first use the bundled config is written to disk so it
    /// can be edited.
    pub fn load(data_dir: PathBuf) -> Self {
        let cfg_path = data_dir.join("yara_config.json");
        let config = match std::fs::read_to_string(&cfg_path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                tracing::warn!("invalid {cfg_path:?}: {e}; using bundled config");
                YaraConfig::bundled()
            }),
            Err(_) => {
                let cfg = YaraConfig::bundled();
                if std::fs::create_dir_all(&data_dir).is_ok() {
                    crate::harden_dir(&data_dir);
                    if std::fs::write(&cfg_path, BUNDLED_CONFIG).is_ok() {
                        crate::harden_file(&cfg_path);
                    }
                }
                cfg
            }
        };
        Self { config, data_dir }
    }

    fn rules_dir(&self) -> PathBuf {
        self.data_dir.join("rules").join(current_os())
    }

    /// Resolve every rule file for the running OS to its text, preferring the
    /// cached copy on disk and falling back to the bundled rule.
    fn rule_sources(&self) -> Vec<(String, String)> {
        let dir = self.rules_dir();
        let mut out = Vec::new();
        for file in self.config.os_rules().rule_files {
            let cached = dir.join(&file);
            if let Ok(text) = std::fs::read_to_string(&cached) {
                out.push((file, text));
            } else if let Some(text) = bundled_rule(&file) {
                out.push((file, text.to_string()));
            } else {
                tracing::warn!("no cached or bundled rules for '{file}'");
            }
        }
        out
    }

    /// Compile the active rule set into an engine, returning any parse warnings.
    pub fn build_engine(&self) -> (YaraEngine, Vec<String>) {
        let sources = self.rule_sources();
        let refs: Vec<(&str, &str)> = sources
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();
        YaraEngine::compile(&refs)
    }

    /// Fetch the latest rule files for the running OS from `rules_repo` and
    /// cache them under `<data_dir>/rules/<os>/`. Failures are collected per
    /// file so one missing rule never aborts the update.
    pub async fn update_rules(&self) -> UpdateReport {
        let mut report = UpdateReport::default();
        let os = current_os();
        let repo = self.config.rules_repo.trim_end_matches('/');
        if repo.is_empty() {
            report.errors.push("rules_repo not configured".into());
            return report;
        }
        // SSRF guard: the rules repo is a config value fetched server-side, so
        // require TLS and reject non-HTTP(S) schemes (file://, etc.).
        if !repo.starts_with("https://") {
            report
                .errors
                .push(format!("refusing non-HTTPS rules_repo: {repo}"));
            return report;
        }

        let dir = self.rules_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            report.errors.push(format!("create {dir:?}: {e}"));
            return report;
        }
        crate::harden_dir(&dir);

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("legion-siem/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                report.errors.push(format!("http client: {e}"));
                return report;
            }
        };

        for file in self.config.os_rules().rule_files {
            let url = format!("{repo}/{os}/{file}");
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match crate::http::text_capped(resp, crate::http::DEFAULT_MAX_BODY).await {
                        Ok(text) => {
                            // Validate before caching so we never persist a broken feed.
                            let (engine, warnings) = YaraEngine::compile(&[(&file, &text)]);
                            if engine.rule_count() == 0 && !warnings.is_empty() {
                                report.failed += 1;
                                report.errors.push(format!(
                                    "{file}: no valid rules ({} warnings)",
                                    warnings.len()
                                ));
                                continue;
                            }
                            let dest = dir.join(&file);
                            match std::fs::write(&dest, &text) {
                                Ok(()) => {
                                    crate::harden_file(&dest);
                                    report.fetched += 1;
                                    report.files.push(file);
                                }
                                Err(e) => {
                                    report.failed += 1;
                                    report.errors.push(format!("{file}: write {e}"));
                                }
                            }
                        }
                        Err(e) => {
                            report.failed += 1;
                            report.errors.push(format!("{file}: body {e}"));
                        }
                    }
                }
                Ok(resp) => {
                    report.failed += 1;
                    report
                        .errors
                        .push(format!("{file}: HTTP {}", resp.status()));
                }
                Err(e) => {
                    report.failed += 1;
                    report.errors.push(format!("{file}: {e}"));
                }
            }
        }
        report
    }

    /// Resolve the roots to scan. When `scan_all_drives` is set (the default),
    /// this is every fixed drive / mount point on the host; otherwise it is the
    /// configured per-OS `scan_paths` with `$VAR`/`${VAR}`/`%VAR%` expanded and
    /// non-existent paths dropped. Falls back to the configured paths if drive
    /// enumeration yields nothing.
    pub fn scan_paths(&self) -> Vec<PathBuf> {
        if self.config.scan_all_drives {
            let roots = crate::fsroots::system_scan_roots();
            if !roots.is_empty() {
                return roots;
            }
        }
        self.config
            .os_rules()
            .scan_paths
            .iter()
            .map(|p| expand_env(p))
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    }
}

/// Replace `$VAR`, `${VAR}` and `%VAR%` references with environment values.
fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '%' {
            if let Some(end) = input[i + 1..].find('%') {
                let name = &input[i + 1..i + 1 + end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i = i + 1 + end + 1;
                continue;
            }
        } else if c == '$' {
            if i + 1 < bytes.len() && bytes[i + 1] as char == '{' {
                if let Some(end) = input[i + 2..].find('}') {
                    let name = &input[i + 2..i + 2 + end];
                    out.push_str(&std::env::var(name).unwrap_or_default());
                    i = i + 2 + end + 1;
                    continue;
                }
            } else {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && is_ident_byte(bytes[j], j == start) {
                    j += 1;
                }
                if j > start {
                    let name = &input[start..j];
                    out.push_str(&std::env::var(name).unwrap_or_default());
                    i = j;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8, _first: bool) -> bool {
    let c = b as char;
    c.is_ascii_alphanumeric() || c == '_'
}

// ───────────────────────────────── Engine ───────────────────────────────────

/// A compiled set of rules ready to scan data.
#[derive(Default)]
pub struct YaraEngine {
    rules: Vec<Rule>,
}

impl YaraEngine {
    /// Compile one rule text into an engine.
    pub fn compile_str(text: &str) -> (Self, Vec<String>) {
        Self::compile(&[("<inline>", text)])
    }

    /// Compile several named rule sources, concatenating their rules. Returns
    /// the engine plus a list of human-readable warnings for skipped rules.
    pub fn compile(sources: &[(&str, &str)]) -> (Self, Vec<String>) {
        let mut rules = Vec::new();
        let mut warnings = Vec::new();
        for (name, text) in sources {
            match parse_rules(text) {
                Ok((mut parsed, mut warns)) => {
                    rules.append(&mut parsed);
                    for w in warns.drain(..) {
                        warnings.push(format!("{name}: {w}"));
                    }
                }
                Err(e) => warnings.push(format!("{name}: {e}")),
            }
        }
        (Self { rules }, warnings)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan an in-memory buffer, labelling any hits with `label`.
    pub fn scan_bytes(&self, label: &str, data: &[u8]) -> Vec<YaraMatch> {
        let now = chrono::Utc::now().to_rfc3339();
        let filesize = data.len() as u64;
        let mut out = Vec::new();
        for rule in &self.rules {
            let counts: Vec<usize> = rule.strings.iter().map(|s| s.matcher.count(data)).collect();
            if eval(&rule.condition, &counts, filesize) {
                let matched: Vec<String> = rule
                    .strings
                    .iter()
                    .zip(&counts)
                    .filter(|(_, &c)| c > 0)
                    .map(|(s, _)| format!("${}", s.id))
                    .collect();
                out.push(YaraMatch {
                    rule: rule.name.clone(),
                    tags: rule.tags.clone(),
                    severity: rule.severity(),
                    description: rule.description(),
                    target: label.to_string(),
                    matched_strings: matched,
                    detected_at: now.clone(),
                });
            }
        }
        out
    }

    /// Scan a single file (skipped if larger than `max_bytes`).
    pub fn scan_file(&self, path: &Path, max_bytes: usize) -> Vec<YaraMatch> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        if !meta.is_file() || meta.len() as usize > max_bytes {
            return Vec::new();
        }
        match std::fs::read(path) {
            Ok(data) => self.scan_bytes(&path.to_string_lossy(), &data),
            Err(_) => Vec::new(),
        }
    }

    /// Recursively scan directories, bounded by `max_bytes` per file and
    /// `max_files` files in total.
    pub fn scan_paths(
        &self,
        roots: &[PathBuf],
        max_bytes: usize,
        max_files: usize,
    ) -> Vec<YaraMatch> {
        let mut out = Vec::new();
        let mut scanned = 0usize;
        for root in roots {
            self.walk(root, max_bytes, max_files, &mut scanned, &mut out);
        }
        out
    }

    fn walk(
        &self,
        path: &Path,
        max_bytes: usize,
        max_files: usize,
        scanned: &mut usize,
        out: &mut Vec<YaraMatch>,
    ) {
        if *scanned >= max_files {
            return;
        }
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.file_type().is_symlink() {
            return; // don't follow symlinks (avoid loops / escapes)
        }
        if meta.is_dir() {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if crate::fsroots::is_excluded_scan_dir(&p) {
                    continue;
                }
                self.walk(&p, max_bytes, max_files, scanned, out);
                if *scanned >= max_files {
                    return;
                }
            }
        } else if meta.is_file() {
            *scanned += 1;
            out.extend(self.scan_file(path, max_bytes));
        }
    }
}

// ──────────────────────────────── Rule model ────────────────────────────────

struct Rule {
    name: String,
    tags: Vec<String>,
    meta: BTreeMap<String, String>,
    strings: Vec<YaraString>,
    condition: Cond,
}

impl Rule {
    fn severity(&self) -> String {
        self.meta
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "Medium".to_string())
    }
    fn description(&self) -> String {
        self.meta
            .get("description")
            .or_else(|| self.meta.get("desc"))
            .cloned()
            .unwrap_or_default()
    }
}

struct YaraString {
    id: String,
    matcher: Matcher,
}

enum Matcher {
    /// One or more concrete byte needles (ascii and/or wide variants).
    Bytes {
        needles: Vec<Vec<u8>>,
        nocase: bool,
        fullword: bool,
    },
    Hex(Vec<HexTok>),
    /// Pattern we could not compile (e.g. regex) — never matches.
    Never,
}

impl Matcher {
    fn count(&self, data: &[u8]) -> usize {
        match self {
            Matcher::Bytes {
                needles,
                nocase,
                fullword,
            } => needles
                .iter()
                .map(|n| count_bytes(data, n, *nocase, *fullword))
                .sum(),
            Matcher::Hex(toks) => count_hex(data, toks),
            Matcher::Never => 0,
        }
    }
}

#[derive(Clone)]
enum HexTok {
    Byte(u8),
    /// High nibble fixed, low wildcard (`A?`).
    MaskHigh(u8),
    /// Low nibble fixed, high wildcard (`?A`).
    MaskLow(u8),
    Any,
    /// Jump `[min-max]`; `max == None` means open-ended.
    Jump(usize, Option<usize>),
}

// ──────────────────────────── Byte / hex matching ───────────────────────────

fn is_word_byte(b: u8) -> bool {
    let c = b as char;
    c.is_ascii_alphanumeric() || c == '_'
}

fn count_bytes(data: &[u8], needle: &[u8], nocase: bool, fullword: bool) -> usize {
    let nl = needle.len();
    if nl == 0 || data.len() < nl {
        return 0;
    }
    let mut count = 0;
    for start in 0..=data.len() - nl {
        let window = &data[start..start + nl];
        let eq = if nocase {
            window
                .iter()
                .zip(needle)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        } else {
            window == needle
        };
        if !eq {
            continue;
        }
        if fullword {
            let before_ok = start == 0 || !is_word_byte(data[start - 1]);
            let after_ok = start + nl == data.len() || !is_word_byte(data[start + nl]);
            if !(before_ok && after_ok) {
                continue;
            }
        }
        count += 1;
    }
    count
}

/// Upper bound on `hex_match_at` invocations per `count_hex` call. Open-ended
/// jumps (`{ 90 [0-] 90 … }`) in a remotely-fetched rule can otherwise fan out
/// exponentially against a large scanned file (audit CORE-2). When the budget is
/// exhausted, matching stops — a pathological rule simply finds no further hits
/// rather than hanging or aborting the process.
const MAX_HEX_STEPS: u64 = 4_000_000;

fn count_hex(data: &[u8], toks: &[HexTok]) -> usize {
    let mut count = 0;
    let mut budget = MAX_HEX_STEPS;
    for start in 0..=data.len() {
        if hex_match_at(data, start, toks, 0, &mut budget) {
            count += 1;
        }
        if budget == 0 {
            break;
        }
    }
    count
}

fn hex_match_at(data: &[u8], pos: usize, toks: &[HexTok], ti: usize, budget: &mut u64) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    if ti == toks.len() {
        return true;
    }
    match &toks[ti] {
        HexTok::Byte(b) => {
            pos < data.len() && data[pos] == *b && hex_match_at(data, pos + 1, toks, ti + 1, budget)
        }
        HexTok::MaskHigh(h) => {
            pos < data.len()
                && (data[pos] >> 4) == *h
                && hex_match_at(data, pos + 1, toks, ti + 1, budget)
        }
        HexTok::MaskLow(l) => {
            pos < data.len()
                && (data[pos] & 0x0f) == *l
                && hex_match_at(data, pos + 1, toks, ti + 1, budget)
        }
        HexTok::Any => pos < data.len() && hex_match_at(data, pos + 1, toks, ti + 1, budget),
        HexTok::Jump(min, max) => {
            let remaining = data.len().saturating_sub(pos);
            let hi = max.unwrap_or(remaining).min(remaining);
            for k in *min..=hi {
                if hex_match_at(data, pos + k, toks, ti + 1, budget) {
                    return true;
                }
                if *budget == 0 {
                    return false;
                }
            }
            false
        }
    }
}

// ─────────────────────────────── Condition AST ──────────────────────────────

enum Cond {
    True,
    False,
    StringRef(usize),
    Count { idx: usize, op: CmpOp, value: i64 },
    Filesize { op: CmpOp, value: i64 },
    Of { quant: Quant, set: Vec<usize> },
    Not(Box<Cond>),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
}

#[derive(Clone, Copy)]
enum Quant {
    All,
    Any,
    N(i64),
}

#[derive(Clone, Copy)]
enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

fn cmp(lhs: i64, op: CmpOp, rhs: i64) -> bool {
    match op {
        CmpOp::Lt => lhs < rhs,
        CmpOp::Le => lhs <= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Ge => lhs >= rhs,
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
    }
}

fn eval(cond: &Cond, counts: &[usize], filesize: u64) -> bool {
    match cond {
        Cond::True => true,
        Cond::False => false,
        Cond::StringRef(i) => counts.get(*i).is_some_and(|&c| c > 0),
        Cond::Count { idx, op, value } => {
            let c = counts.get(*idx).copied().unwrap_or(0) as i64;
            cmp(c, *op, *value)
        }
        Cond::Filesize { op, value } => cmp(filesize as i64, *op, *value),
        Cond::Of { quant, set } => {
            let matched = set
                .iter()
                .filter(|&&i| counts.get(i).is_some_and(|&c| c > 0))
                .count();
            match quant {
                Quant::All => !set.is_empty() && matched == set.len(),
                Quant::Any => matched >= 1,
                Quant::N(n) => matched as i64 >= *n,
            }
        }
        Cond::Not(a) => !eval(a, counts, filesize),
        Cond::And(a, b) => eval(a, counts, filesize) && eval(b, counts, filesize),
        Cond::Or(a, b) => eval(a, counts, filesize) || eval(b, counts, filesize),
    }
}

// ───────────────────────────────── Lexer ────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    HexBody(String),
    Regex(String),
    Num(i64),
    StringId(String),
    CountId(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Comma,
    Eq,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Star,
    /// Any punctuation outside the supported subset (`.`, `@`, `+`, …). Kept as
    /// a token so lexing never aborts; the parser rejects rules that use it.
    Other(char),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut out = Vec::new();
    // True when the previous significant token was `=`, so a following `{` or
    // `/` is a hex/regex literal rather than a brace/comment.
    let mut prev_eq = false;

    while i < n {
        let c = b[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // comments
        if c == '/' && i + 1 < n && b[i + 1] as char == '/' {
            while i < n && b[i] as char != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && b[i + 1] as char == '*' {
            i += 2;
            while i + 1 < n && !(b[i] as char == '*' && b[i + 1] as char == '/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        // hex body  $a = { .. }
        if c == '{' && prev_eq {
            i += 1;
            let start = i;
            while i < n && b[i] as char != '}' {
                i += 1;
            }
            out.push(Tok::HexBody(src[start..i].to_string()));
            if i < n {
                i += 1;
            }
            prev_eq = false;
            continue;
        }
        // regex  $a = /.../
        if c == '/' && prev_eq {
            i += 1;
            let start = i;
            while i < n && b[i] as char != '/' {
                if b[i] as char == '\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push(Tok::Regex(src[start..i.min(n)].to_string()));
            if i < n {
                i += 1;
            }
            while i < n && (b[i] as char).is_ascii_alphabetic() {
                i += 1; // regex modifiers
            }
            prev_eq = false;
            continue;
        }
        // string literal
        if c == '"' {
            i += 1;
            let mut s = String::new();
            while i < n && b[i] as char != '"' {
                if b[i] as char == '\\' && i + 1 < n {
                    i += 1;
                    match b[i] as char {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        'x' if i + 2 < n => {
                            if let Ok(v) = u8::from_str_radix(&src[i + 1..i + 3], 16) {
                                s.push(v as char);
                                i += 2;
                            }
                        }
                        other => s.push(other),
                    }
                    i += 1;
                } else {
                    s.push(b[i] as char);
                    i += 1;
                }
            }
            if i < n {
                i += 1;
            }
            out.push(Tok::Str(s));
            prev_eq = false;
            continue;
        }
        // $id / #id
        if c == '$' || c == '#' {
            i += 1;
            let start = i;
            while i < n && is_ident_byte(b[i], i == start) {
                i += 1;
            }
            let id = src[start..i].to_string();
            out.push(if c == '$' {
                Tok::StringId(id)
            } else {
                Tok::CountId(id)
            });
            prev_eq = false;
            continue;
        }
        // number (decimal or 0x..)
        if c.is_ascii_digit() {
            let start = i;
            let value = if c == '0' && i + 1 < n && matches!(b[i + 1] as char, 'x' | 'X') {
                i += 2;
                let hs = i;
                while i < n && (b[i] as char).is_ascii_hexdigit() {
                    i += 1;
                }
                i64::from_str_radix(&src[hs..i], 16).unwrap_or(0)
            } else {
                while i < n && (b[i] as char).is_ascii_digit() {
                    i += 1;
                }
                src[start..i].parse().unwrap_or(0)
            };
            out.push(Tok::Num(value));
            prev_eq = false;
            continue;
        }
        // identifier / keyword
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < n && is_ident_byte(b[i], i == start) {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_string()));
            prev_eq = false;
            continue;
        }
        // punctuation / operators
        match c {
            '{' => {
                out.push(Tok::LBrace);
                i += 1;
                prev_eq = false;
            }
            '}' => {
                out.push(Tok::RBrace);
                i += 1;
                prev_eq = false;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
                prev_eq = false;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
                prev_eq = false;
            }
            ':' => {
                out.push(Tok::Colon);
                i += 1;
                prev_eq = false;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
                prev_eq = false;
            }
            '*' => {
                out.push(Tok::Star);
                i += 1;
                prev_eq = false;
            }
            '=' => {
                if i + 1 < n && b[i + 1] as char == '=' {
                    out.push(Tok::EqEq);
                    i += 2;
                    prev_eq = false;
                } else {
                    out.push(Tok::Eq);
                    i += 1;
                    prev_eq = true;
                }
            }
            '!' if i + 1 < n && b[i + 1] as char == '=' => {
                out.push(Tok::Ne);
                i += 2;
                prev_eq = false;
            }
            '<' => {
                if i + 1 < n && b[i + 1] as char == '=' {
                    out.push(Tok::Le);
                    i += 2;
                } else {
                    out.push(Tok::Lt);
                    i += 1;
                }
                prev_eq = false;
            }
            '>' => {
                if i + 1 < n && b[i + 1] as char == '=' {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    out.push(Tok::Gt);
                    i += 1;
                }
                prev_eq = false;
            }
            other => {
                // Unknown punctuation: keep as a token so the file still lexes;
                // any rule that relies on it will fail to parse and be skipped.
                out.push(Tok::Other(other));
                i += 1;
                prev_eq = false;
            }
        }
    }
    Ok(out)
}

// ───────────────────────────────── Parser ───────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn peek2(&self) -> Option<&Tok> {
        self.toks.get(self.pos + 1)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, t: &Tok) -> Result<(), String> {
        match self.peek() {
            Some(x) if x == t => {
                self.pos += 1;
                Ok(())
            }
            other => Err(format!("expected {t:?}, found {other:?}")),
        }
    }
    fn is_ident(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s == kw)
    }
}

/// Parse a whole file into rules, recovering from individual rule errors.
fn parse_rules(text: &str) -> Result<(Vec<Rule>, Vec<String>), String> {
    let toks = lex(text)?;
    let mut p = Parser { toks, pos: 0 };
    let mut rules = Vec::new();
    let mut warnings = Vec::new();

    while p.peek().is_some() {
        // skip leading modifiers / imports
        if p.is_ident("import") {
            p.next();
            p.next(); // the string
            continue;
        }
        if p.is_ident("global") || p.is_ident("private") {
            p.next();
            continue;
        }
        if p.is_ident("rule") {
            let start = p.pos;
            match parse_rule(&mut p) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    let name = rule_name_at(&p.toks, start);
                    warnings.push(format!("rule {name}: {e} (skipped)"));
                    recover_to_next_rule(&mut p);
                }
            }
            continue;
        }
        // unknown top-level token — skip it
        p.next();
    }
    Ok((rules, warnings))
}

fn rule_name_at(toks: &[Tok], rule_pos: usize) -> String {
    match toks.get(rule_pos + 1) {
        Some(Tok::Ident(s)) => s.clone(),
        _ => "<unnamed>".to_string(),
    }
}

fn recover_to_next_rule(p: &mut Parser) {
    // Advance to the next top-level `rule` keyword (best effort).
    while let Some(t) = p.peek() {
        if matches!(t, Tok::Ident(s) if s == "rule") {
            return;
        }
        p.pos += 1;
    }
}

fn parse_rule(p: &mut Parser) -> Result<Rule, String> {
    p.eat(&Tok::Ident("rule".into()))?;
    let name = match p.next() {
        Some(Tok::Ident(s)) => s,
        other => return Err(format!("expected rule name, found {other:?}")),
    };

    let mut tags = Vec::new();
    if matches!(p.peek(), Some(Tok::Colon)) {
        p.next();
        while let Some(Tok::Ident(t)) = p.peek() {
            tags.push(t.clone());
            p.next();
        }
    }

    p.eat(&Tok::LBrace)?;

    let mut meta = BTreeMap::new();
    let mut strings: Vec<YaraString> = Vec::new();
    let mut condition: Option<Cond> = None;

    loop {
        match p.peek() {
            Some(Tok::RBrace) => break,
            Some(Tok::Ident(s)) if s == "meta" && matches!(p.peek2(), Some(Tok::Colon)) => {
                p.next();
                p.next();
                parse_meta(p, &mut meta);
            }
            Some(Tok::Ident(s)) if s == "strings" && matches!(p.peek2(), Some(Tok::Colon)) => {
                p.next();
                p.next();
                parse_strings(p, &mut strings)?;
            }
            Some(Tok::Ident(s)) if s == "condition" && matches!(p.peek2(), Some(Tok::Colon)) => {
                p.next();
                p.next();
                condition = Some(parse_condition(p, &strings)?);
            }
            other => return Err(format!("unexpected token in rule body: {other:?}")),
        }
    }
    p.eat(&Tok::RBrace)?;

    let condition = condition.ok_or("missing condition")?;
    Ok(Rule {
        name,
        tags,
        meta,
        strings,
        condition,
    })
}

fn parse_meta(p: &mut Parser, meta: &mut BTreeMap<String, String>) {
    loop {
        // stop at a new section or the end of the rule
        match p.peek() {
            Some(Tok::Ident(s))
                if (s == "strings" || s == "condition" || s == "meta")
                    && matches!(p.peek2(), Some(Tok::Colon)) =>
            {
                break
            }
            Some(Tok::Ident(_)) if matches!(p.peek2(), Some(Tok::Eq)) => {
                let key = match p.next() {
                    Some(Tok::Ident(k)) => k,
                    _ => break,
                };
                p.next(); // '='
                let value = match p.next() {
                    Some(Tok::Str(s)) => s,
                    Some(Tok::Num(n)) => n.to_string(),
                    Some(Tok::Ident(b)) => b, // true / false
                    _ => String::new(),
                };
                meta.insert(key, value);
            }
            _ => break,
        }
    }
}

fn parse_strings(p: &mut Parser, strings: &mut Vec<YaraString>) -> Result<(), String> {
    while let Some(Tok::StringId(id)) = p.peek().cloned() {
        p.next();
        p.eat(&Tok::Eq)?;
        let matcher = match p.next() {
            Some(Tok::Str(s)) => parse_text_modifiers(p, s),
            Some(Tok::HexBody(h)) => Matcher::Hex(parse_hex(&h)?),
            Some(Tok::Regex(_)) => Matcher::Never, // regex unsupported — never matches
            other => return Err(format!("expected string literal, found {other:?}")),
        };
        strings.push(YaraString { id, matcher });
    }
    Ok(())
}

fn parse_text_modifiers(p: &mut Parser, literal: String) -> Matcher {
    let mut nocase = false;
    let mut fullword = false;
    let mut wide = false;
    let mut ascii = false;
    while let Some(Tok::Ident(m)) = p.peek() {
        match m.as_str() {
            "nocase" => nocase = true,
            "fullword" => fullword = true,
            "wide" => wide = true,
            "ascii" => ascii = true,
            // accepted-and-ignored modifiers
            "private" | "xor" | "base64" | "base64wide" => {}
            _ => break,
        }
        p.next();
    }

    let base = literal.into_bytes();
    let mut needles = Vec::new();
    // default (no wide/ascii) == ascii
    if ascii || !wide {
        needles.push(base.clone());
    }
    if wide {
        let mut w = Vec::with_capacity(base.len() * 2);
        for byte in &base {
            w.push(*byte);
            w.push(0);
        }
        needles.push(w);
    }
    Matcher::Bytes {
        needles,
        nocase,
        fullword,
    }
}

fn parse_hex(body: &str) -> Result<Vec<HexTok>, String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '[' {
            // jump [n], [n-m], [n-]
            let mut inner = String::new();
            i += 1;
            while i < chars.len() && chars[i] != ']' {
                inner.push(chars[i]);
                i += 1;
            }
            i += 1; // ']'
            let inner = inner.trim();
            let (min, max) = if let Some((a, b)) = inner.split_once('-') {
                let min = a.trim().parse::<usize>().map_err(|_| "bad jump")?;
                let max = if b.trim().is_empty() {
                    None
                } else {
                    Some(b.trim().parse::<usize>().map_err(|_| "bad jump")?)
                };
                (min, max)
            } else {
                let v = inner.parse::<usize>().map_err(|_| "bad jump")?;
                (v, Some(v))
            };
            toks.push(HexTok::Jump(min, max));
            continue;
        }
        if c == '(' || c == ')' || c == '|' {
            // hex alternation is unsupported in this subset
            return Err("hex alternation not supported".into());
        }
        // a nibble pair
        if i + 1 >= chars.len() {
            return Err("dangling hex nibble".into());
        }
        let hi = chars[i];
        let lo = chars[i + 1];
        i += 2;
        match (hi, lo) {
            ('?', '?') => toks.push(HexTok::Any),
            ('?', l) => toks.push(HexTok::MaskLow(hex_nibble(l)?)),
            (h, '?') => toks.push(HexTok::MaskHigh(hex_nibble(h)?)),
            (h, l) => toks.push(HexTok::Byte((hex_nibble(h)? << 4) | hex_nibble(l)?)),
        }
    }
    // Cap token count so the recursive matcher's depth (one frame per token on a
    // linear chain) cannot be driven to a stack overflow by a huge fetched rule
    // (audit CORE-2).
    const MAX_HEX_TOKENS: usize = 4096;
    if toks.len() > MAX_HEX_TOKENS {
        return Err(format!(
            "hex string too long: {} tokens (max {MAX_HEX_TOKENS})",
            toks.len()
        ));
    }
    if toks.is_empty() {
        return Err("empty hex string".into());
    }
    Ok(toks)
}

fn hex_nibble(c: char) -> Result<u8, String> {
    c.to_digit(16)
        .map(|d| d as u8)
        .ok_or_else(|| format!("invalid hex nibble '{c}'"))
}

// ── condition expression (precedence: not > and > or) ──

fn parse_condition(p: &mut Parser, strings: &[YaraString]) -> Result<Cond, String> {
    parse_or(p, strings)
}

fn parse_or(p: &mut Parser, strings: &[YaraString]) -> Result<Cond, String> {
    let mut lhs = parse_and(p, strings)?;
    while p.is_ident("or") {
        p.next();
        let rhs = parse_and(p, strings)?;
        lhs = Cond::Or(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_and(p: &mut Parser, strings: &[YaraString]) -> Result<Cond, String> {
    let mut lhs = parse_not(p, strings)?;
    while p.is_ident("and") {
        p.next();
        let rhs = parse_not(p, strings)?;
        lhs = Cond::And(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_not(p: &mut Parser, strings: &[YaraString]) -> Result<Cond, String> {
    if p.is_ident("not") {
        p.next();
        let inner = parse_not(p, strings)?;
        return Ok(Cond::Not(Box::new(inner)));
    }
    parse_primary(p, strings)
}

fn parse_primary(p: &mut Parser, strings: &[YaraString]) -> Result<Cond, String> {
    match p.peek().cloned() {
        Some(Tok::LParen) => {
            p.next();
            let inner = parse_or(p, strings)?;
            p.eat(&Tok::RParen)?;
            Ok(inner)
        }
        Some(Tok::Ident(kw)) if kw == "true" => {
            p.next();
            Ok(Cond::True)
        }
        Some(Tok::Ident(kw)) if kw == "false" => {
            p.next();
            Ok(Cond::False)
        }
        Some(Tok::Ident(kw)) if kw == "filesize" => {
            p.next();
            let op = parse_cmp(p)?;
            let value = parse_number_with_unit(p)?;
            Ok(Cond::Filesize { op, value })
        }
        Some(Tok::Ident(kw)) if kw == "all" || kw == "any" => {
            p.next();
            let quant = if kw == "all" { Quant::All } else { Quant::Any };
            parse_of(p, strings, quant)
        }
        // `N of …`
        Some(Tok::Num(n)) => {
            // could be `N of them` or a bare number comparison (rare) — only support `of`.
            p.next();
            if p.is_ident("of") {
                parse_of(p, strings, Quant::N(n))
            } else {
                Err("bare number in condition not supported".into())
            }
        }
        Some(Tok::StringId(id)) => {
            p.next();
            let idx =
                resolve_string(strings, &id).ok_or_else(|| format!("unknown string ${id}"))?;
            Ok(Cond::StringRef(idx))
        }
        Some(Tok::CountId(id)) => {
            p.next();
            let idx =
                resolve_string(strings, &id).ok_or_else(|| format!("unknown string #{id}"))?;
            let op = parse_cmp(p)?;
            let value = parse_number_with_unit(p)?;
            Ok(Cond::Count { idx, op, value })
        }
        other => Err(format!("unexpected token in condition: {other:?}")),
    }
}

/// Parse the tail of a quantifier: `of them` or `of ($a, $b*)`.
fn parse_of(p: &mut Parser, strings: &[YaraString], quant: Quant) -> Result<Cond, String> {
    if !p.is_ident("of") {
        return Err("expected 'of'".into());
    }
    p.next();
    let set = if p.is_ident("them") {
        p.next();
        (0..strings.len()).collect()
    } else {
        p.eat(&Tok::LParen)?;
        let mut set = Vec::new();
        loop {
            match p.next() {
                Some(Tok::StringId(id)) => {
                    // wildcard `$a*`
                    if matches!(p.peek(), Some(Tok::Star)) {
                        p.next();
                        for (i, s) in strings.iter().enumerate() {
                            if s.id.starts_with(&id) {
                                set.push(i);
                            }
                        }
                    } else if let Some(i) = resolve_string(strings, &id) {
                        set.push(i);
                    } else {
                        return Err(format!("unknown string ${id} in set"));
                    }
                }
                Some(Tok::Star) => {
                    // `($*)` — all strings
                    set.extend(0..strings.len());
                }
                other => return Err(format!("unexpected token in string set: {other:?}")),
            }
            match p.peek() {
                Some(Tok::Comma) => {
                    p.next();
                }
                Some(Tok::RParen) => {
                    p.next();
                    break;
                }
                other => return Err(format!("expected ',' or ')' in set, found {other:?}")),
            }
        }
        set
    };
    Ok(Cond::Of { quant, set })
}

fn parse_cmp(p: &mut Parser) -> Result<CmpOp, String> {
    let op = match p.peek() {
        Some(Tok::Lt) => CmpOp::Lt,
        Some(Tok::Le) => CmpOp::Le,
        Some(Tok::Gt) => CmpOp::Gt,
        Some(Tok::Ge) => CmpOp::Ge,
        Some(Tok::EqEq) => CmpOp::Eq,
        Some(Tok::Ne) => CmpOp::Ne,
        other => return Err(format!("expected comparison operator, found {other:?}")),
    };
    p.next();
    Ok(op)
}

fn parse_number_with_unit(p: &mut Parser) -> Result<i64, String> {
    let n = match p.next() {
        Some(Tok::Num(n)) => n,
        other => return Err(format!("expected number, found {other:?}")),
    };
    let mult: Option<i64> = match p.peek() {
        Some(Tok::Ident(u)) => match u.to_ascii_uppercase().as_str() {
            "KB" => Some(1024),
            "MB" => Some(1024 * 1024),
            "GB" => Some(1024 * 1024 * 1024),
            _ => None,
        },
        _ => None,
    };
    if let Some(m) = mult {
        p.next();
        // A malicious rule (e.g. `filesize < 99999999999999 GB`) must not panic
        // on multiply overflow in debug or silently wrap in release (audit CORE-7).
        n.checked_mul(m)
            .ok_or_else(|| format!("filesize value overflow: {n} * {m}"))
    } else {
        Ok(n)
    }
}

fn resolve_string(strings: &[YaraString], id: &str) -> Option<usize> {
    strings.iter().position(|s| s.id == id)
}

// ───────────────────────────────── Tests ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(src: &str) -> YaraEngine {
        let (e, warns) = YaraEngine::compile_str(src);
        assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
        e
    }

    #[test]
    fn text_string_match() {
        let e = engine(r#"rule R { strings: $a = "hello" condition: $a }"#);
        assert_eq!(e.scan_bytes("t", b"say hello world").len(), 1);
        assert_eq!(e.scan_bytes("t", b"nothing here").len(), 0);
    }

    #[test]
    fn nocase_and_fullword() {
        let e = engine(r#"rule R { strings: $a = "Test" nocase fullword condition: $a }"#);
        assert_eq!(e.scan_bytes("t", b"this is a TEST!").len(), 1);
        // fullword should reject when embedded in a larger word
        assert_eq!(e.scan_bytes("t", b"testing").len(), 0);
    }

    #[test]
    fn hex_with_wildcards_and_jump() {
        let e = engine(r#"rule R { strings: $h = { 4D 5A ?? 90 [0-2] AB } condition: $h }"#);
        assert_eq!(e.scan_bytes("t", &[0x4D, 0x5A, 0x01, 0x90, 0xAB]).len(), 1);
        assert_eq!(
            e.scan_bytes("t", &[0x4D, 0x5A, 0x01, 0x90, 0x00, 0x00, 0xAB])
                .len(),
            1
        );
        assert_eq!(e.scan_bytes("t", &[0x4D, 0x5A, 0x01, 0x91, 0xAB]).len(), 0);
    }

    #[test]
    fn nibble_masks() {
        let e = engine(r#"rule R { strings: $h = { 4? ?A } condition: $h }"#);
        assert_eq!(e.scan_bytes("t", &[0x4F, 0x3A]).len(), 1);
        assert_eq!(e.scan_bytes("t", &[0x5F, 0x3A]).len(), 0);
    }

    #[test]
    fn filesize_unit_overflow_does_not_panic() {
        // Audit CORE-7: a huge `filesize` literal must surface as a compile
        // warning, not a multiply-overflow panic.
        let (e, warns) =
            YaraEngine::compile_str(r#"rule R { condition: filesize < 99999999999999999 GB }"#);
        assert_eq!(e.rule_count(), 0, "overflowing rule must not compile");
        assert!(!warns.is_empty(), "expected a compile warning");
    }

    #[test]
    fn oversized_hex_string_is_rejected() {
        // Audit CORE-2: a hex pattern beyond the token cap must be rejected at
        // compile time so the recursive matcher's depth stays bounded.
        let huge = "90 ".repeat(5000);
        let src = format!("rule R {{ strings: $h = {{ {huge} }} condition: $h }}");
        let (e, warns) = YaraEngine::compile_str(&src);
        assert_eq!(e.rule_count(), 0, "oversized hex rule must not compile");
        assert!(!warns.is_empty());
    }

    #[test]
    fn open_ended_jumps_terminate_under_budget() {
        // Audit CORE-2: chained open-ended jumps against a sizeable buffer must
        // complete (bounded by the step budget) rather than hang or overflow.
        let e = engine(r#"rule R { strings: $h = { 90 [0-] 90 [0-] 90 [0-] 90 } condition: $h }"#);
        let data = vec![0x90u8; 4096];
        // Just needs to return without panicking / hanging.
        let _ = e.scan_bytes("t", &data);
    }

    #[test]
    fn condition_of_them_and_count() {
        let e = engine(
            r#"rule R {
                strings:
                    $a = "aaa"
                    $b = "bbb"
                    $c = "ccc"
                condition:
                    2 of them
            }"#,
        );
        assert_eq!(e.scan_bytes("t", b"aaa bbb").len(), 1);
        assert_eq!(e.scan_bytes("t", b"aaa only").len(), 0);

        let e2 = engine(r#"rule R { strings: $a = "x" condition: #a >= 3 }"#);
        assert_eq!(e2.scan_bytes("t", b"x x x x").len(), 1);
        assert_eq!(e2.scan_bytes("t", b"x x").len(), 0);
    }

    #[test]
    fn boolean_and_groups() {
        let e = engine(
            r#"rule R {
                strings:
                    $a = "alpha"
                    $b = "beta"
                    $c = "gamma"
                condition:
                    $a and (any of ($b, $c))
            }"#,
        );
        assert_eq!(e.scan_bytes("t", b"alpha gamma").len(), 1);
        assert_eq!(e.scan_bytes("t", b"alpha only").len(), 0);
        assert_eq!(e.scan_bytes("t", b"beta gamma").len(), 0);
    }

    #[test]
    fn filesize_condition() {
        let e = engine(r#"rule R { strings: $a = "z" condition: $a and filesize < 10 }"#);
        assert_eq!(e.scan_bytes("t", b"zzz").len(), 1);
        assert_eq!(e.scan_bytes("t", b"zzzzzzzzzzzzzzz").len(), 0);
    }

    #[test]
    fn meta_severity_and_tags() {
        let e = engine(
            r#"rule R : malware dropper {
                meta:
                    description = "demo"
                    severity = "Critical"
                strings:
                    $a = "boom"
                condition:
                    $a
            }"#,
        );
        let hits = e.scan_bytes("t", b"boom");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "Critical");
        assert_eq!(hits[0].description, "demo");
        assert_eq!(hits[0].tags, vec!["malware", "dropper"]);
        assert_eq!(hits[0].matched_strings, vec!["$a"]);
    }

    #[test]
    fn bad_rule_is_skipped_not_fatal() {
        let src = r#"
            rule Good { strings: $a = "ok" condition: $a }
            rule Bad  { condition: pe.entry_point == 0 }
            rule Good2 { strings: $b = "fine" condition: $b }
        "#;
        let (e, warns) = YaraEngine::compile_str(src);
        assert_eq!(e.rule_count(), 2, "good rules should survive");
        assert!(!warns.is_empty(), "bad rule should warn");
    }

    #[test]
    fn bundled_rules_compile_cleanly() {
        for (name, text) in [
            ("common.yar", BUNDLED_COMMON),
            ("linux.yar", BUNDLED_LINUX),
            ("windows.yar", BUNDLED_WINDOWS),
        ] {
            let (e, warns) = YaraEngine::compile(&[(name, text)]);
            assert!(warns.is_empty(), "{name} produced warnings: {warns:?}");
            assert!(e.rule_count() > 0, "{name} produced no rules");
        }
    }

    #[test]
    fn eicar_detection() {
        let (e, _) = YaraEngine::compile(&[("common.yar", BUNDLED_COMMON)]);
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let hits = e.scan_bytes("eicar.txt", eicar);
        assert!(hits.iter().any(|h| h.rule == "EICAR_Test_File"));
    }

    #[test]
    fn bundled_config_parses() {
        let cfg = YaraConfig::bundled();
        assert!(!cfg.rules_repo.is_empty());
        assert!(cfg.os.contains_key("linux"));
        assert!(cfg.os.contains_key("windows"));
    }
}
