//! Configuration module
//!
//! Provides structured configuration for the Rustinel agent.
//! Configuration can be loaded from:
//! 1. Default values (hardcoded)
//! 2. config.toml file (optional)
//! 3. Environment variables with EDR__ prefix
//!
//! Example environment variable override:
//! EDR__LOGGING__LEVEL=debug
//! EDR__SCANNER__SIGMA_RULES_PATH=custom/path

use serde::Deserialize;
use std::path::PathBuf;

use crate::models::MatchDebugLevel;

/// Main application configuration
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub scanner: ScannerConfig,
    pub logging: LogConfig,
    pub alerts: AlertConfig,
    pub allowlist: AllowlistConfig,
    pub response: ResponseConfig,
    pub network: NetworkConfig,
    pub ioc: IocConfig,
}

/// Scanner configuration (Sigma and YARA rules)
#[derive(Debug, Deserialize)]
pub struct ScannerConfig {
    pub sigma_enabled: bool,
    pub sigma_rules_path: PathBuf,
    pub yara_enabled: bool,
    pub yara_rules_path: PathBuf,
    pub yara_allowlist_paths: Vec<String>,
}

/// Global allowlist configuration shared across modules
#[derive(Debug, Deserialize)]
pub struct AllowlistConfig {
    /// Trusted directory prefixes, applied to response/IOC hash/YARA scan
    pub paths: Vec<String>,
}

/// Operational logging configuration (application debug logs)
#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub level: String,
    /// Optional tracing filter expression. If set, overrides `level`.
    pub filter: Option<String>,
    pub directory: PathBuf,
    pub filename: String,
    pub console_output: bool,
}

/// Security alerts configuration (JSON output for SIEM)
#[derive(Debug, Deserialize)]
pub struct AlertConfig {
    pub directory: PathBuf,
    pub filename: String,
    pub match_debug: MatchDebugLevel,
}

/// Active response configuration (optional prevention/termination)
#[derive(Debug, Deserialize)]
pub struct ResponseConfig {
    pub enabled: bool,
    pub prevention_enabled: bool,
    pub min_severity: String,
    pub channel_capacity: usize,
    pub allowlist_images: Vec<String>,
    pub allowlist_paths: Vec<String>,
}

/// Network event aggregation configuration
#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    /// Enable connection aggregation to reduce event volume
    pub aggregation_enabled: bool,
    /// Maximum number of unique connections to track
    pub aggregation_max_entries: usize,
    /// Number of inter-connection intervals to store for beacon detection
    pub aggregation_interval_buffer_size: usize,
}

/// Atomic IOC detection configuration
#[derive(Debug, Deserialize)]
pub struct IocConfig {
    pub enabled: bool,
    pub hashes_path: PathBuf,
    pub ips_path: PathBuf,
    pub domains_path: PathBuf,
    pub paths_regex_path: PathBuf,
    pub default_severity: String,
    pub max_file_size_mb: u64,
    pub hash_allowlist_paths: Vec<String>,
}

impl AppConfig {
    /// Load configuration from defaults, config.toml, and environment variables
    pub fn new() -> Result<Self, config::ConfigError> {
        let s = config::Config::builder()
            // --- Defaults ---
            // Scanner
            .set_default("scanner.sigma_enabled", true)?
            .set_default("scanner.sigma_rules_path", "rules/sigma")?
            .set_default("scanner.yara_enabled", true)?
            .set_default("scanner.yara_rules_path", "rules/yara")?
            .set_default("scanner.yara_allowlist_paths", Vec::<String>::new())?
            // Logging
            .set_default("logging.level", "info")?
            .set_default("logging.directory", "logs")?
            .set_default("logging.filename", "rustinel.log")?
            .set_default("logging.console_output", true)?
            // Alerts
            .set_default("alerts.directory", "logs")?
            .set_default("alerts.filename", "alerts.json")?
            .set_default("alerts.match_debug", "off")?
            // Global allowlist
            .set_default(
                "allowlist.paths",
                vec![
                    "C:\\Windows\\".to_string(),
                    "C:\\Program Files\\".to_string(),
                    "C:\\Program Files (x86)\\".to_string(),
                ],
            )?
            // Active Response
            .set_default("response.enabled", false)?
            .set_default("response.prevention_enabled", false)?
            .set_default("response.min_severity", "critical")?
            .set_default("response.channel_capacity", 128)?
            .set_default("response.allowlist_images", Vec::<String>::new())?
            .set_default("response.allowlist_paths", Vec::<String>::new())?
            // Network
            .set_default("network.aggregation_enabled", true)?
            .set_default("network.aggregation_max_entries", 20000)?
            .set_default("network.aggregation_interval_buffer_size", 50)?
            // IOC
            .set_default("ioc.enabled", true)?
            .set_default("ioc.hashes_path", "rules/ioc/hashes.txt")?
            .set_default("ioc.ips_path", "rules/ioc/ips.txt")?
            .set_default("ioc.domains_path", "rules/ioc/domains.txt")?
            .set_default("ioc.paths_regex_path", "rules/ioc/paths_regex.txt")?
            .set_default("ioc.default_severity", "high")?
            .set_default("ioc.max_file_size_mb", 50)?
            .set_default("ioc.hash_allowlist_paths", Vec::<String>::new())?
            // --- Sources ---
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("EDR").separator("__"))
            .build()?;

        let mut cfg: Self = s.try_deserialize()?;
        cfg.apply_allowlist_fallbacks();
        Ok(cfg)
    }

    fn apply_allowlist_fallbacks(&mut self) {
        if self.response.allowlist_paths.is_empty() {
            self.response.allowlist_paths = self.allowlist.paths.clone();
        }

        if self.ioc.hash_allowlist_paths.is_empty() {
            self.ioc.hash_allowlist_paths = self.allowlist.paths.clone();
        }

        if self.scanner.yara_allowlist_paths.is_empty() {
            self.scanner.yara_allowlist_paths = self.allowlist.paths.clone();
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut cfg = Self {
            scanner: ScannerConfig {
                sigma_enabled: true,
                sigma_rules_path: PathBuf::from("rules/sigma"),
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules/yara"),
                yara_allowlist_paths: Vec::new(),
            },
            logging: LogConfig {
                level: "info".to_string(),
                filter: None,
                directory: PathBuf::from("logs"),
                filename: "rustinel.log".to_string(),
                console_output: true,
            },
            alerts: AlertConfig {
                directory: PathBuf::from("logs"),
                filename: "alerts.json".to_string(),
                match_debug: MatchDebugLevel::Off,
            },
            allowlist: AllowlistConfig {
                paths: vec![
                    "C:\\Windows\\".to_string(),
                    "C:\\Program Files\\".to_string(),
                    "C:\\Program Files (x86)\\".to_string(),
                ],
            },
            response: ResponseConfig {
                enabled: false,
                prevention_enabled: false,
                min_severity: "critical".to_string(),
                channel_capacity: 128,
                allowlist_images: Vec::new(),
                allowlist_paths: Vec::new(),
            },
            network: NetworkConfig {
                aggregation_enabled: true,
                aggregation_max_entries: 20_000,
                aggregation_interval_buffer_size: 50,
            },
            ioc: IocConfig {
                enabled: true,
                hashes_path: PathBuf::from("rules/ioc/hashes.txt"),
                ips_path: PathBuf::from("rules/ioc/ips.txt"),
                domains_path: PathBuf::from("rules/ioc/domains.txt"),
                paths_regex_path: PathBuf::from("rules/ioc/paths_regex.txt"),
                default_severity: "high".to_string(),
                max_file_size_mb: 50,
                hash_allowlist_paths: Vec::new(),
            },
        };

        cfg.apply_allowlist_fallbacks();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_loads_defaults() {
        let cfg = AppConfig::new().unwrap();
        assert!(cfg.scanner.sigma_enabled);
        assert_eq!(cfg.logging.level, "info");
        assert!(cfg.logging.filter.is_none());
        assert!(cfg.logging.console_output);
        assert!(!cfg.response.enabled);
        assert!(!cfg.response.prevention_enabled);
        assert_eq!(cfg.response.min_severity, "critical");
        assert!(cfg.ioc.enabled);
        assert_eq!(cfg.ioc.default_severity, "high");
        assert_eq!(cfg.alerts.match_debug, MatchDebugLevel::Off);
    }

    #[test]
    fn test_config_paths() {
        let cfg = AppConfig::new().unwrap();
        assert_eq!(cfg.scanner.sigma_rules_path, PathBuf::from("rules/sigma"));
        assert_eq!(cfg.scanner.yara_rules_path, PathBuf::from("rules/yara"));
        assert_eq!(cfg.ioc.hashes_path, PathBuf::from("rules/ioc/hashes.txt"));
        assert_eq!(cfg.ioc.ips_path, PathBuf::from("rules/ioc/ips.txt"));
        assert_eq!(
            cfg.ioc.paths_regex_path,
            PathBuf::from("rules/ioc/paths_regex.txt")
        );
    }

    #[test]
    fn test_global_allowlist_propagates_to_modules() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.response.allowlist_paths, cfg.allowlist.paths);
        assert_eq!(cfg.ioc.hash_allowlist_paths, cfg.allowlist.paths);
        assert_eq!(cfg.scanner.yara_allowlist_paths, cfg.allowlist.paths);
    }

    #[test]
    fn test_module_specific_allowlist_not_overwritten() {
        let mut cfg = AppConfig::default();
        // Reset to simulate module-specific override scenario
        cfg.allowlist.paths = vec!["C:\\Shared\\".to_string()];
        cfg.response.allowlist_paths = vec!["C:\\ResponseOnly\\".to_string()];
        cfg.ioc.hash_allowlist_paths = Vec::new();
        cfg.scanner.yara_allowlist_paths = Vec::new();
        cfg.apply_allowlist_fallbacks();

        assert_eq!(
            cfg.response.allowlist_paths,
            vec!["C:\\ResponseOnly\\".to_string()]
        );
        assert_eq!(
            cfg.ioc.hash_allowlist_paths,
            vec!["C:\\Shared\\".to_string()]
        );
        assert_eq!(
            cfg.scanner.yara_allowlist_paths,
            vec!["C:\\Shared\\".to_string()]
        );
    }
}
