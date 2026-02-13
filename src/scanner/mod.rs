//! Yara scanner module
//!
//! Handles compiling rules, listening for process events, and scanning files.

use anyhow::{Context, Result};
use ferrisetw::parser::Parser;
use ferrisetw::EventRecord;
use std::fs;
use std::path::Path;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use yara_x::{Compiler, Rules, Scanner as XScanner};

use crate::collector::EventHandler;
use crate::models::{EventCategory, MatchDebugLevel, YaraRuleMatch, YaraStringMatch};

fn normalize_yara_path(nt_path: &str) -> String {
    let cleaned = nt_path.strip_prefix("\\??\\").unwrap_or(nt_path);
    crate::utils::convert_nt_to_dos(cleaned)
}

pub fn normalize_allowlist_paths(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| {
            let mut normalized = value.trim().replace('/', "\\").to_ascii_lowercase();
            if !normalized.ends_with('\\') {
                normalized.push('\\');
            }
            normalized
        })
        .collect()
}

pub fn is_path_allowlisted(path: &str, allowlist_paths: &[String]) -> bool {
    if allowlist_paths.is_empty() {
        return false;
    }

    let normalized = path.trim().replace('/', "\\").to_ascii_lowercase();
    allowlist_paths
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
}

const MAX_YARA_STRINGS_PER_RULE: usize = 8;
const MAX_YARA_SNIPPET_LEN: usize = 80;

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    if max_len <= 3 {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }

    let limit = max_len - 3;
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str("...");
    out
}

/// Main Scanner struct holding compiled rules
pub struct Scanner {
    rules: Rules,
}

impl Scanner {
    /// Compile all .yar files in a directory
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Result<Self> {
        let rules_dir = rules_dir.as_ref();
        let mut compiler = Compiler::new();
        let mut files_found = 0;
        let mut files_compiled = 0;

        info!("Loading YARA rules from: {:?}", rules_dir);

        if rules_dir.exists() && rules_dir.is_dir() {
            for entry in fs::read_dir(rules_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        files_found += 1;
                        debug!("Found YARA rule file: {:?}", path);
                        let src = fs::read_to_string(&path)
                            .with_context(|| format!("Failed to read {:?}", path))?;

                        match compiler.add_source(src.as_str()) {
                            Ok(_) => {
                                files_compiled += 1;
                                debug!("✓ Compiled YARA rule: {:?}", path);
                            }
                            Err(e) => {
                                warn!("✗ Failed to compile {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        } else {
            warn!(
                "YARA rules directory does not exist or is not a directory: {:?}",
                rules_dir
            );
        }

        let rules = compiler.build();
        info!(
            "YARA Scanner: Found {} rule files, compiled {} successfully",
            files_found, files_compiled
        );
        Ok(Self { rules })
    }

    /// Scan a file path and return matching rule details
    pub fn scan_file(
        &self,
        path: &str,
        match_debug: MatchDebugLevel,
    ) -> Result<Vec<YaraRuleMatch>> {
        let mut matches = Vec::new();
        let mut scanner = XScanner::new(&self.rules);

        // Scan the file
        match scanner.scan_file(path) {
            Ok(scan_results) => {
                for rule in scan_results.matching_rules() {
                    let rule_name = rule.identifier().to_string();
                    let include_meta = !matches!(match_debug, MatchDebugLevel::Off);
                    let include_strings = matches!(match_debug, MatchDebugLevel::Full);

                    let tags = if include_meta {
                        rule.tags()
                            .map(|tag| tag.identifier().to_string())
                            .collect()
                    } else {
                        Vec::new()
                    };

                    let namespace = if include_meta {
                        Some(rule.namespace().to_string())
                    } else {
                        None
                    };

                    let mut strings = Vec::new();
                    if include_strings {
                        let mut count = 0usize;
                        for pattern in rule.patterns() {
                            let pattern_id = pattern.identifier().to_string();
                            for m in pattern.matches() {
                                if count >= MAX_YARA_STRINGS_PER_RULE {
                                    break;
                                }
                                let offset = m.range().start as u64;
                                let snippet_raw = String::from_utf8_lossy(m.data()).to_string();
                                let snippet = truncate_str(&snippet_raw, MAX_YARA_SNIPPET_LEN);

                                strings.push(YaraStringMatch {
                                    id: pattern_id.clone(),
                                    offset: Some(offset),
                                    snippet: Some(snippet),
                                });

                                count += 1;
                            }
                            if count >= MAX_YARA_STRINGS_PER_RULE {
                                break;
                            }
                        }
                    }

                    matches.push(YaraRuleMatch {
                        rule: rule_name,
                        tags,
                        namespace,
                        strings,
                    });
                }
            }
            Err(e) => {
                // File locking issues are common in EDR; keep these at trace to avoid debug spam.
                tracing::trace!(
                    target: "scanner",
                    file = %path,
                    error = %e,
                    "Skipping YARA scan"
                );
            }
        }

        Ok(matches)
    }
}

/// ETW Handler that sends file paths to the background worker
pub struct YaraEventHandler {
    pub tx: Sender<(String, u32)>, // Sends (FilePath, PID)
    pub allowlist_paths: Vec<String>,
}

fn extract_process_id(parser: &Parser, record: &EventRecord) -> u32 {
    // Kernel-Process ProcessStart events report the *parent* PID in the header.
    // Prefer the payload ProcessID when present.
    if let Ok(pid) = parser.try_parse::<u32>("ProcessID") {
        return pid;
    }
    if let Ok(pid) = parser.try_parse::<u32>("ProcessId") {
        return pid;
    }
    if let Ok(pid) = parser.try_parse::<u64>("ProcessID") {
        return pid as u32;
    }
    if let Ok(pid) = parser.try_parse::<u64>("ProcessId") {
        return pid as u32;
    }
    record.process_id()
}

impl EventHandler for YaraEventHandler {
    fn handle_event(&self, record: &EventRecord, category: EventCategory) {
        // We only care about Process Start (OpCode 1) events
        if category == EventCategory::Process && record.opcode() == 1 {
            tracing::trace!(
                target: "scanner",
                pid = record.process_id(),
                "YARA ProcessStart event detected"
            );

            // We use a lightweight parser just to get ImageName
            if let Ok(schema) =
                ferrisetw::schema_locator::SchemaLocator::default().event_schema(record)
            {
                let parser = Parser::create(record, &schema);

                // Try to get the ImageName (path)
                if let Ok(nt_path) = parser.try_parse::<String>("ImageName") {
                    let pid = extract_process_id(&parser, record);
                    if pid != record.process_id() {
                        tracing::trace!(
                            target: "scanner",
                            payload_pid = pid,
                            header_pid = record.process_id(),
                            "YARA payload PID differs from header PID"
                        );
                    }
                    tracing::trace!(
                        target: "scanner",
                        pid = pid,
                        nt_path = %nt_path,
                        "YARA extracted NT image path"
                    );

                    // Convert NT Device path to DOS path using shared mapper.
                    // Handle Win32 prefix before conversion.
                    let dos_path = normalize_yara_path(&nt_path);

                    if is_path_allowlisted(&dos_path, &self.allowlist_paths) {
                        tracing::trace!(
                            target: "scanner",
                            pid = pid,
                            file = %dos_path,
                            "YARA skipping allowlisted path"
                        );
                        return;
                    }

                    tracing::trace!(
                        target: "scanner",
                        pid = pid,
                        file = %dos_path,
                        "YARA converted path to DOS format"
                    );

                    // Send to background worker (non-blocking)
                    match self.tx.try_send((dos_path.clone(), pid)) {
                        Ok(_) => tracing::trace!(
                            target: "scanner",
                            pid = pid,
                            file = %dos_path,
                            "YARA queued file for scan"
                        ),
                        Err(e) => warn!(
                            target: "scanner",
                            pid = pid,
                            file = %dos_path,
                            error = %e,
                            "YARA queue full; dropping scan job"
                        ),
                    }
                } else {
                    tracing::trace!(
                        target: "scanner",
                        pid = record.process_id(),
                        "YARA failed to parse ImageName from ProcessStart event"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        // Test that we can create a scanner even with an empty/missing directory
        let result = Scanner::new("nonexistent_dir");
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_yara_path_strips_win32_prefix() {
        let input = r"\??\C:\Windows\System32\cmd.exe";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn test_normalize_yara_path_passthrough() {
        let input = r"C:\Temp\edrust.exe";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, input);
    }

    #[test]
    fn test_normalize_allowlist_paths_adds_trailing_separator() {
        let paths = vec![r"C:\Windows".to_string()];
        let normalized = normalize_allowlist_paths(&paths);
        assert_eq!(normalized, vec![r"c:\windows\".to_string()]);
    }

    #[test]
    fn test_is_path_allowlisted_matches_prefix() {
        let allowlist = vec![r"c:\windows\".to_string()];
        assert!(is_path_allowlisted(
            r"C:\Windows\System32\cmd.exe",
            &allowlist
        ));
        assert!(!is_path_allowlisted(r"C:\Temp\evil.exe", &allowlist));
    }
}
