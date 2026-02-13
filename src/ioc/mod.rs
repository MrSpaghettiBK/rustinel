//! Atomic IOC detection engine.
//!
//! Supports hash, IP/CIDR, domain, and path-regex matching.

use crate::config::IocConfig;
use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
    ProcessCreationFields,
};
use digest::Digest;
use ipnetwork::IpNetwork;
use md5::Md5;
use regex::{Regex, RegexSet, RegexSetBuilder};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const HASH_CACHE_MAX_ENTRIES: usize = 10_000;
const HASH_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

#[derive(Debug, Clone, Copy)]
pub struct HashRequirements {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

#[derive(Debug, Clone)]
pub struct ComputedHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IocMatch {
    pub kind: IocKind,
    pub indicator: String,
    pub observed: String,
    pub comment: Option<String>,
    pub source: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Md5,
    Sha1,
    Sha256,
    Ip,
    Domain,
    PathRegex,
}

impl IocKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IocKind::Md5 => "md5",
            IocKind::Sha1 => "sha1",
            IocKind::Sha256 => "sha256",
            IocKind::Ip => "ip",
            IocKind::Domain => "domain",
            IocKind::PathRegex => "path_regex",
        }
    }
}

#[derive(Debug, Clone)]
struct IocMeta {
    comment: Option<String>,
    source: String,
    line: usize,
}

#[derive(Debug, Clone, Default)]
struct HashIocs {
    md5: HashMap<String, IocMeta>,
    sha1: HashMap<String, IocMeta>,
    sha256: HashMap<String, IocMeta>,
}

#[derive(Debug, Clone, Default)]
struct IpIocs {
    exact: HashMap<IpAddr, IocMeta>,
    cidr: Vec<(IpNetwork, IocMeta)>,
}

#[derive(Debug, Clone, Default)]
struct DomainIocs {
    exact: HashMap<String, IocMeta>,
    suffix: Vec<(String, IocMeta)>,
}

#[derive(Debug, Clone, Default)]
struct PathIocs {
    regex_set: Option<RegexSet>,
    patterns: Vec<(String, IocMeta)>,
}

#[derive(Debug, Clone)]
pub struct IocStats {
    pub md5: usize,
    pub sha1: usize,
    pub sha256: usize,
    pub ip: usize,
    pub cidr: usize,
    pub domain_exact: usize,
    pub domain_suffix: usize,
    pub path_regex: usize,
}

pub struct IocEngine {
    enabled: bool,
    severity: AlertSeverity,
    hash_iocs: HashIocs,
    ip_iocs: IpIocs,
    domain_iocs: DomainIocs,
    path_iocs: PathIocs,
    max_file_size_bytes: u64,
    hash_allowlist_paths: Vec<String>,
}

impl IocEngine {
    pub fn load(cfg: &IocConfig) -> Self {
        if !cfg.enabled {
            return Self::disabled();
        }

        let severity = parse_severity(&cfg.default_severity);

        let hash_iocs = load_hashes(&cfg.hashes_path);
        let ip_iocs = load_ips(&cfg.ips_path);
        let domain_iocs = load_domains(&cfg.domains_path);
        let path_iocs = load_path_regexes(&cfg.paths_regex_path);

        let max_file_size_bytes = cfg.max_file_size_mb * 1024 * 1024;
        let hash_allowlist_paths: Vec<String> = cfg
            .hash_allowlist_paths
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect();

        if !hash_allowlist_paths.is_empty() {
            info!(
                target: "ioc",
                count = hash_allowlist_paths.len(),
                "Hash allowlist paths loaded (files under these paths will NOT be hashed)"
            );
        }

        Self {
            enabled: true,
            severity,
            hash_iocs,
            ip_iocs,
            domain_iocs,
            path_iocs,
            max_file_size_bytes,
            hash_allowlist_paths,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            severity: AlertSeverity::Low,
            hash_iocs: HashIocs::default(),
            ip_iocs: IpIocs::default(),
            domain_iocs: DomainIocs::default(),
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn stats(&self) -> IocStats {
        IocStats {
            md5: self.hash_iocs.md5.len(),
            sha1: self.hash_iocs.sha1.len(),
            sha256: self.hash_iocs.sha256.len(),
            ip: self.ip_iocs.exact.len(),
            cidr: self.ip_iocs.cidr.len(),
            domain_exact: self.domain_iocs.exact.len(),
            domain_suffix: self.domain_iocs.suffix.len(),
            path_regex: self.path_iocs.patterns.len(),
        }
    }

    pub fn hash_requirements(&self) -> HashRequirements {
        HashRequirements {
            md5: !self.hash_iocs.md5.is_empty(),
            sha1: !self.hash_iocs.sha1.is_empty(),
            sha256: !self.hash_iocs.sha256.is_empty(),
        }
    }

    pub fn wants_hashing(&self) -> bool {
        let req = self.hash_requirements();
        req.md5 || req.sha1 || req.sha256
    }

    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_bytes
    }

    pub fn is_hash_allowlisted(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.hash_allowlist_paths
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    }

    pub fn check_event(&self, event: &NormalizedEvent) -> Vec<IocMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        self.match_domains(event, &mut matches, &mut seen);
        self.match_ips(event, &mut matches, &mut seen);
        self.match_paths(event, &mut matches, &mut seen);

        matches
    }

    pub fn match_hashes(&self, hashes: &ComputedHashes) -> Vec<IocMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut matches = Vec::new();

        if let Some(value) = hashes.md5.as_deref() {
            if let Some(meta) = self.hash_iocs.md5.get(value) {
                matches.push(build_match(IocKind::Md5, value, value, meta));
            }
        }

        if let Some(value) = hashes.sha1.as_deref() {
            if let Some(meta) = self.hash_iocs.sha1.get(value) {
                matches.push(build_match(IocKind::Sha1, value, value, meta));
            }
        }

        if let Some(value) = hashes.sha256.as_deref() {
            if let Some(meta) = self.hash_iocs.sha256.get(value) {
                matches.push(build_match(IocKind::Sha256, value, value, meta));
            }
        }

        matches
    }

    pub fn build_alert_for_match(&self, m: &IocMatch, event: &NormalizedEvent) -> Alert {
        Alert {
            severity: self.severity,
            rule_name: ioc_rule_name(m),
            rule_description: ioc_rule_description(m),
            engine: DetectionEngine::Ioc,
            event: event.clone(),
            match_details: None,
        }
    }

    pub fn build_alert_for_hash_match(&self, m: &IocMatch, path: &str, pid: u32) -> Alert {
        Alert {
            severity: self.severity,
            rule_name: ioc_rule_name(m),
            rule_description: ioc_rule_description(m),
            engine: DetectionEngine::Ioc,
            event: NormalizedEvent {
                timestamp: crate::utils::now_timestamp_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some(path.to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    command_line: None,
                    process_id: Some(pid.to_string()),
                    parent_process_id: None,
                    parent_image: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
            match_details: None,
        }
    }

    fn match_domains(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_name {
                    candidates.push(v.as_str());
                }
            }
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_hostname {
                    candidates.push(v.as_str());
                }
            }
            EventFields::WmiEvent(f) => {
                if let Some(v) = &f.destination_hostname {
                    candidates.push(v.as_str());
                }
            }
            _ => {}
        }

        for candidate in candidates {
            let normalized = normalize_domain(candidate);
            let Some(host) = normalized else { continue };

            if let Some(meta) = self.domain_iocs.exact.get(&host) {
                push_match_unique(
                    matches,
                    seen,
                    build_match(IocKind::Domain, &host, &host, meta),
                );
            }

            for (suffix, meta) in &self.domain_iocs.suffix {
                if host == *suffix || host.ends_with(&format!(".{}", suffix)) {
                    let indicator = format!(".{}", suffix);
                    push_match_unique(
                        matches,
                        seen,
                        build_match(IocKind::Domain, &indicator, &host, meta),
                    );
                }
            }
        }
    }

    fn match_ips(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::NetworkConnection(f) => {
                if let Some(v) = &f.destination_ip {
                    candidates.push(v.as_str());
                }
                if let Some(v) = &f.source_ip {
                    candidates.push(v.as_str());
                }
            }
            EventFields::DnsQuery(f) => {
                if let Some(v) = &f.query_results {
                    for ip in extract_ips(v) {
                        candidates.push(ip);
                    }
                }
            }
            _ => {}
        }

        for candidate in candidates {
            if let Ok(ip) = candidate.parse::<IpAddr>() {
                if let Some(meta) = self.ip_iocs.exact.get(&ip) {
                    let indicator = ip.to_string();
                    push_match_unique(
                        matches,
                        seen,
                        build_match(IocKind::Ip, &indicator, candidate, meta),
                    );
                }

                for (network, meta) in &self.ip_iocs.cidr {
                    if network.contains(ip) {
                        let indicator = network.to_string();
                        push_match_unique(
                            matches,
                            seen,
                            build_match(IocKind::Ip, &indicator, candidate, meta),
                        );
                    }
                }
            }
        }
    }

    fn match_paths(
        &self,
        event: &NormalizedEvent,
        matches: &mut Vec<IocMatch>,
        seen: &mut HashSet<String>,
    ) {
        let Some(regex_set) = &self.path_iocs.regex_set else {
            tracing::trace!(target: "ioc", "match_paths: regex_set is None, skipping");
            return;
        };

        let mut candidates = Vec::new();

        match &event.fields {
            EventFields::ProcessCreation(f) => {
                if let Some(v) = &f.image {
                    candidates.push(v.as_str());
                }
                if let Some(v) = &f.target_image {
                    candidates.push(v.as_str());
                }
            }
            EventFields::FileEvent(f) => {
                if let Some(v) = &f.target_filename {
                    candidates.push(v.as_str());
                }
            }
            EventFields::ImageLoad(f) => {
                if let Some(v) = &f.image_loaded {
                    candidates.push(v.as_str());
                }
            }
            EventFields::PowerShellScript(f) => {
                if let Some(v) = &f.path {
                    candidates.push(v.as_str());
                }
            }
            EventFields::ServiceCreation(f) => {
                if let Some(v) = &f.service_file_name {
                    candidates.push(v.as_str());
                }
            }
            _ => {}
        }

        for candidate in candidates {
            tracing::trace!(
                target: "ioc",
                candidate = %candidate,
                patterns = self.path_iocs.patterns.len(),
                "match_paths: testing candidate against regex set"
            );
            for idx in regex_set.matches(candidate).iter() {
                if let Some((pattern, meta)) = self.path_iocs.patterns.get(idx) {
                    push_match_unique(
                        matches,
                        seen,
                        build_match(IocKind::PathRegex, pattern, candidate, meta),
                    );
                }
            }
        }
    }
}

fn ioc_rule_name(m: &IocMatch) -> String {
    format!("ioc:{}:{}", m.kind.as_str(), m.indicator)
}

fn ioc_rule_description(m: &IocMatch) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(comment) = &m.comment {
        parts.push(comment.clone());
    }
    if m.observed != m.indicator {
        parts.push(format!("observed: {}", m.observed));
    }
    parts.push(format!("source: {}", m.source));
    Some(parts.join(" | "))
}

fn build_match(kind: IocKind, indicator: &str, observed: &str, meta: &IocMeta) -> IocMatch {
    IocMatch {
        kind,
        indicator: indicator.to_string(),
        observed: observed.to_string(),
        comment: meta.comment.clone(),
        source: meta.source.clone(),
        line: meta.line,
    }
}

fn push_match_unique(matches: &mut Vec<IocMatch>, seen: &mut HashSet<String>, m: IocMatch) {
    let key = format!(
        "{}:{}:{}:{}:{}",
        m.kind.as_str(),
        m.indicator,
        m.observed,
        m.source,
        m.line
    );
    if seen.insert(key) {
        matches.push(m);
    }
}

fn parse_severity(value: &str) -> AlertSeverity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        other => {
            warn!(
                target: "ioc",
                severity = %other,
                "Unknown ioc.default_severity; defaulting to high"
            );
            AlertSeverity::High
        }
    }
}

fn split_value_and_comment(line: &str) -> (String, Option<String>) {
    let mut parts = line.splitn(2, ';');
    let value = parts.next().unwrap_or("").trim().to_string();
    let comment = parts
        .next()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    (value, comment)
}

fn should_skip_line(line: &str) -> bool {
    line.is_empty() || line.starts_with('#') || line.starts_with("//")
}

fn read_lines(path: &Path) -> Vec<(usize, String)> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            warn!(
                target: "ioc",
                path = ?path,
                error = %err,
                "IOC file missing or unreadable"
            );
            return Vec::new();
        }
    };

    content
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line.to_string()))
        .collect()
}

fn load_hashes(path: &Path) -> HashIocs {
    let mut iocs = HashIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let normalized = value.to_ascii_lowercase();
        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        if !is_hex(&normalized) {
            warn!(
                target: "ioc",
                path = %source,
                line = line_no,
                value = %value,
                "Invalid hash (non-hex), skipping"
            );
            continue;
        }

        match normalized.len() {
            32 => {
                iocs.md5.insert(normalized, meta);
            }
            40 => {
                iocs.sha1.insert(normalized, meta);
            }
            64 => {
                iocs.sha256.insert(normalized, meta);
            }
            _ => {
                warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    "Invalid hash length, skipping"
                );
            }
        }
    }

    info!(
        target: "ioc",
        md5 = iocs.md5.len(),
        sha1 = iocs.sha1.len(),
        sha256 = iocs.sha256.len(),
        "Loaded hash IOCs"
    );

    iocs
}

fn load_ips(path: &Path) -> IpIocs {
    let mut iocs = IpIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        if value.contains('/') {
            match value.parse::<IpNetwork>() {
                Ok(network) => iocs.cidr.push((network, meta)),
                Err(err) => warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    error = %err,
                    "Invalid CIDR, skipping"
                ),
            }
        } else {
            match value.parse::<IpAddr>() {
                Ok(ip) => {
                    iocs.exact.insert(ip, meta);
                }
                Err(err) => warn!(
                    target: "ioc",
                    path = %source,
                    line = line_no,
                    value = %value,
                    error = %err,
                    "Invalid IP, skipping"
                ),
            }
        }
    }

    info!(
        target: "ioc",
        ip = iocs.exact.len(),
        cidr = iocs.cidr.len(),
        "Loaded IP IOCs"
    );

    iocs
}

fn load_domains(path: &Path) -> DomainIocs {
    let mut iocs = DomainIocs::default();
    let source = path.display().to_string();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        let meta = IocMeta {
            comment,
            source: source.clone(),
            line: line_no,
        };

        let mut normalized = value.to_ascii_lowercase();
        normalized = normalized.trim_end_matches('.').to_string();

        if normalized.starts_with("*.") {
            normalized = format!(".{}", normalized.trim_start_matches("*."));
        }

        if normalized.starts_with('.') {
            let suffix = normalized.trim_start_matches('.').to_string();
            if !suffix.is_empty() {
                iocs.suffix.push((suffix, meta));
            }
        } else {
            iocs.exact.insert(normalized, meta);
        }
    }

    info!(
        target: "ioc",
        exact = iocs.exact.len(),
        suffix = iocs.suffix.len(),
        "Loaded domain IOCs"
    );

    iocs
}

fn load_path_regexes(path: &Path) -> PathIocs {
    let mut iocs = PathIocs::default();
    let source = path.display().to_string();
    let mut patterns = Vec::new();

    for (line_no, line) in read_lines(path) {
        let line = line.trim();
        if should_skip_line(line) {
            continue;
        }

        let (value, comment) = split_value_and_comment(line);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        if let Err(err) = Regex::new(value) {
            warn!(
                target: "ioc",
                path = %source,
                line = line_no,
                pattern = %value,
                error = %err,
                "Invalid path regex, skipping"
            );
            continue;
        }

        iocs.patterns.push((
            value.to_string(),
            IocMeta {
                comment,
                source: source.clone(),
                line: line_no,
            },
        ));
        patterns.push(value.to_string());
    }

    if !patterns.is_empty() {
        let regex_set = RegexSetBuilder::new(patterns)
            .case_insensitive(true)
            .build();
        match regex_set {
            Ok(set) => iocs.regex_set = Some(set),
            Err(err) => warn!(
                target: "ioc",
                path = %source,
                error = %err,
                "Failed to build path regex set"
            ),
        }
    }

    info!(
        target: "ioc",
        count = iocs.patterns.len(),
        "Loaded path regex IOCs"
    );

    iocs
}

fn normalize_domain(value: &str) -> Option<String> {
    let mut host = value.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

fn extract_ips(value: &str) -> Vec<&str> {
    value
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|token| !token.is_empty())
        .collect()
}

fn is_hex(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileIdentity {
    path: String,
    size: u64,
    mtime: u64,
}

#[derive(Debug, Clone)]
struct HashCacheEntry {
    hashes: ComputedHashes,
    timestamp: u64,
}

pub struct HashCache {
    entries: HashMap<FileIdentity, HashCacheEntry>,
    max_entries: usize,
    ttl_secs: u64,
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new()
    }
}

impl HashCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: HASH_CACHE_MAX_ENTRIES,
            ttl_secs: HASH_CACHE_TTL_SECS,
        }
    }

    pub fn get_or_compute(
        &mut self,
        path: &Path,
        requirements: HashRequirements,
        buf: &mut [u8],
    ) -> anyhow::Result<ComputedHashes> {
        let identity = file_identity(path);
        if let Some(identity) = &identity {
            if let Some(entry) = self.entries.get(identity) {
                if !self.is_expired(entry) {
                    return Ok(entry.hashes.clone());
                }
            }
        }

        let hashes = compute_hashes(path, requirements, buf)?;
        if let Some(identity) = identity {
            let now = now_secs();
            self.entries.insert(
                identity,
                HashCacheEntry {
                    hashes: hashes.clone(),
                    timestamp: now,
                },
            );
            if self.entries.len() > self.max_entries {
                self.trim();
            }
        }

        Ok(hashes)
    }

    fn is_expired(&self, entry: &HashCacheEntry) -> bool {
        now_secs().saturating_sub(entry.timestamp) > self.ttl_secs
    }

    fn trim(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }

        let mut timestamps: Vec<u64> = self.entries.values().map(|entry| entry.timestamp).collect();
        timestamps.sort_unstable();
        let cutoff = timestamps[self.entries.len() / 2];
        self.entries.retain(|_, entry| entry.timestamp >= cutoff);

        if self.entries.len() > self.max_entries {
            let extra = self.entries.len() - self.max_entries;
            let keys: Vec<FileIdentity> = self.entries.keys().take(extra).cloned().collect();
            for key in keys {
                self.entries.remove(&key);
            }
        }
    }
}

fn compute_hashes(
    path: &Path,
    requirements: HashRequirements,
    buf: &mut [u8],
) -> anyhow::Result<ComputedHashes> {
    let mut file = fs::File::open(path)?;

    let mut md5_hasher = requirements.md5.then(Md5::new);
    let mut sha1_hasher = requirements.sha1.then(Sha1::new);
    let mut sha256_hasher = requirements.sha256.then(Sha256::new);

    loop {
        let read = file.read(buf)?;
        if read == 0 {
            break;
        }
        if let Some(hasher) = md5_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
        if let Some(hasher) = sha1_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
        if let Some(hasher) = sha256_hasher.as_mut() {
            hasher.update(&buf[..read]);
        }
    }

    Ok(ComputedHashes {
        md5: md5_hasher.map(|h| hex::encode(h.finalize())),
        sha1: sha1_hasher.map(|h| hex::encode(h.finalize())),
        sha256: sha256_hasher.map(|h| hex::encode(h.finalize())),
    })
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_default();

    Some(FileIdentity {
        path: path.display().to_string(),
        size,
        mtime,
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventFields;

    #[test]
    fn test_domain_suffix_match() {
        let mut domains = DomainIocs::default();
        domains.suffix.push((
            "example.com".to_string(),
            IocMeta {
                comment: None,
                source: "test".to_string(),
                line: 1,
            },
        ));

        let engine = IocEngine {
            enabled: true,
            severity: AlertSeverity::High,
            hash_iocs: HashIocs::default(),
            ip_iocs: IpIocs::default(),
            domain_iocs: domains,
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        };

        let event = NormalizedEvent {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            category: EventCategory::Dns,
            event_id: 22,
            event_id_string: "22".to_string(),
            opcode: 0,
            fields: EventFields::DnsQuery(crate::models::DnsQueryFields {
                query_name: Some("foo.example.com".to_string()),
                query_results: None,
                query_status: None,
                process_id: None,
                image: None,
            }),
            process_context: None,
        };

        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Domain);
    }

    #[test]
    fn test_hash_length_detection() {
        let mut hashes = HashIocs::default();
        hashes.md5.insert(
            "0c2674c3a97c53082187d930efb645c2".to_string(),
            IocMeta {
                comment: None,
                source: "test".to_string(),
                line: 1,
            },
        );

        let engine = IocEngine {
            enabled: true,
            severity: AlertSeverity::High,
            hash_iocs: hashes,
            ip_iocs: IpIocs::default(),
            domain_iocs: DomainIocs::default(),
            path_iocs: PathIocs::default(),
            max_file_size_bytes: 0,
            hash_allowlist_paths: Vec::new(),
        };

        let matches = engine.match_hashes(&ComputedHashes {
            md5: Some("0c2674c3a97c53082187d930efb645c2".to_string()),
            sha1: None,
            sha256: None,
        });

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, IocKind::Md5);
    }
}
