# Configuration

Rustinel loads configuration from four sources in order of precedence:

1. CLI flags (highest, run mode only)
2. Environment variables
3. `config.toml` in the current working directory
4. Built-in defaults (lowest)

## Configuration File

Place `config.toml` in the current working directory when you start Rustinel. The
file name is resolved as `config` by the config loader, so `config.toml` is the
recommended format.

For service deployments, the working directory is the service process directory
(often `C:\Windows\System32`). Use absolute paths or environment overrides for
rules and log locations.

```toml
[scanner]
sigma_enabled = true
sigma_rules_path = "rules/sigma"
yara_enabled = true
yara_rules_path = "rules/yara"

[allowlist]
paths = [
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Program Files (x86)\\",
]

[logging]
level = "info"
# Optional target-aware override (takes precedence over level when set)
# filter = "info,engine=info,scanner=info,ioc=info,rustinel::normalizer=info"
directory = "logs"
filename = "rustinel.log"
console_output = true

[alerts]
directory = "logs"
filename = "alerts.json"

[response]
enabled = false
prevention_enabled = false
min_severity = "critical"
channel_capacity = 128
allowlist_images = []

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_interval_buffer_size = 50

[ioc]
enabled = true
hashes_path = "rules/ioc/hashes.txt"
ips_path = "rules/ioc/ips.txt"
domains_path = "rules/ioc/domains.txt"
paths_regex_path = "rules/ioc/paths_regex.txt"
default_severity = "high"
max_file_size_mb = 50
```

## Options

### Scanner

| Option | Default | Description |
|--------|---------|-------------|
| `sigma_enabled` | `true` | Enable Sigma rule engine |
| `sigma_rules_path` | `rules/sigma` | Path to Sigma rules directory (relative to working directory unless absolute) |
| `yara_enabled` | `true` | Enable YARA scanner |
| `yara_rules_path` | `rules/yara` | Path to YARA rules directory (relative to working directory unless absolute) |
| `yara_allowlist_paths` | inherits `allowlist.paths` | Prefix paths skipped by YARA scan queue/worker (case-insensitive). Optional module-specific override |

### Global Allowlist

| Option | Default | Description |
|--------|---------|-------------|
| `paths` | `["C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\"]` | Shared trusted path prefixes propagated to Response/IOC hash/YARA unless module-specific overrides are set |

Propagation behavior:
- If `response.allowlist_paths` is empty, it inherits `allowlist.paths`.
- If `ioc.hash_allowlist_paths` is empty, it inherits `allowlist.paths`.
- If `scanner.yara_allowlist_paths` is empty, it inherits `allowlist.paths`.
- Setting a module-specific list disables inheritance for that module only.

### Logging

| Option | Default | Description |
|--------|---------|-------------|
| `level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `filter` | `null` | Optional `tracing_subscriber` filter expression (for example: `info,engine=trace,scanner=debug`). When set and valid, this overrides `level`. |
| `directory` | `logs` | Log output directory |
| `filename` | `rustinel.log` | Log filename (daily rotation applied) |
| `console_output` | `true` | Mirror logs to stdout |

Rule logic evaluation errors from Sigma are only emitted at `warn`, `debug`, or `trace` levels.

### Alerts

| Option | Default | Description |
|--------|---------|-------------|
| `directory` | `logs` | Alert output directory |
| `filename` | `alerts.json` | Alert filename (NDJSON, daily rotation) |

### Active Response

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable active response engine |
| `prevention_enabled` | `false` | If `false`, log dry-run actions only |
| `min_severity` | `critical` | Minimum severity to respond to: `low`, `medium`, `high`, `critical` |
| `channel_capacity` | `128` | Queue size for response tasks (drops on overflow) |
| `allowlist_images` | `[]` | Image basenames or full paths to skip |
| `allowlist_paths` | inherits `allowlist.paths` | Prefix paths to skip (case-insensitive). Optional module-specific override |

See `docs/active-response.md` for behavior and testing guidance.

### Network

| Option | Default | Description |
|--------|---------|-------------|
| `aggregation_enabled` | `true` | Enable connection aggregation to reduce event volume |
| `aggregation_max_entries` | `20000` | Maximum unique connections to track |
| `aggregation_interval_buffer_size` | `50` | Intervals to store for beacon detection |

Connection aggregation suppresses repeated connections from the same process to the same destination,
emitting only the first connection. Timing data is collected for future beacon detection analysis.

### IOC (Atomic Indicators)

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable atomic IOC detection |
| `hashes_path` | `rules/ioc/hashes.txt` | Hash IOC file (MD5/SHA1/SHA256) |
| `ips_path` | `rules/ioc/ips.txt` | IP and CIDR IOC file |
| `domains_path` | `rules/ioc/domains.txt` | Domain IOC file |
| `paths_regex_path` | `rules/ioc/paths_regex.txt` | Path/filename regex IOC file |
| `default_severity` | `high` | Severity assigned to IOC alerts |
| `max_file_size_mb` | `50` | Skip hashing files larger than this (MB). Set to `0` to disable the limit |
| `hash_allowlist_paths` | inherits `allowlist.paths` | Prefix paths to skip hashing (case-insensitive). Optional module-specific override |

Path regexes are compiled case-insensitive by default (Windows path semantics).
Hash IOCs are evaluated on process start only in a dedicated blocking worker thread.
Files under allowlisted paths (shared `allowlist.paths` by default) and files exceeding `max_file_size_mb` are skipped.
A file identity cache (path + size + mtime) avoids re-hashing unchanged binaries.

## Environment Variables

Override any setting using the `EDR__` prefix with double underscore separators:

```powershell
$env:EDR__LOGGING__LEVEL="debug"
$env:EDR__LOGGING__FILTER="info,engine=debug,scanner=info,ioc=debug,rustinel::normalizer=info"
$env:EDR__SCANNER__SIGMA_RULES_PATH="C:\\custom\\sigma"
$env:EDR__SCANNER__YARA_RULES_PATH="C:\\custom\\yara"
$env:EDR__ALLOWLIST__PATHS='["C:\\Windows\\","C:\\Program Files\\"]'
# optional module-specific override:
$env:EDR__SCANNER__YARA_ALLOWLIST_PATHS='["C:\\Windows\\","D:\\Trusted\\"]'

rustinel run
```

## CLI Overrides

Only the log level can be overridden via CLI:

```powershell
rustinel run --log-level debug
```

CLI flags apply to `run` only. Service management commands do not pass flags to the service process.

## Examples

### Minimal Config (Sigma Only)

```toml
[scanner]
yara_enabled = false
```

### Debug Mode

```toml
[logging]
level = "debug"
console_output = true
```

### Custom Paths

```toml
[scanner]
sigma_rules_path = "C:\\SecurityRules\\sigma"
yara_rules_path = "C:\\SecurityRules\\yara"

[logging]
directory = "C:\\Logs\\Rustinel"

[alerts]
directory = "C:\\Logs\\Rustinel"
```
