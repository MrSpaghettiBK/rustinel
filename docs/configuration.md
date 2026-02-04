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

[logging]
level = "info"
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
allowlist_paths = [
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Program Files (x86)\\",
]

[network]
aggregation_enabled = true
aggregation_max_entries = 20000
aggregation_interval_buffer_size = 50
```

## Options

### Scanner

| Option | Default | Description |
|--------|---------|-------------|
| `sigma_enabled` | `true` | Enable Sigma rule engine |
| `sigma_rules_path` | `rules/sigma` | Path to Sigma rules directory (relative to working directory unless absolute) |
| `yara_enabled` | `true` | Enable YARA scanner |
| `yara_rules_path` | `rules/yara` | Path to YARA rules directory (relative to working directory unless absolute) |

### Logging

| Option | Default | Description |
|--------|---------|-------------|
| `level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
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
| `allowlist_paths` | `[...]` | Prefix paths to skip (case-insensitive) |

See `docs/active-response.md` for behavior and testing guidance.

### Network

| Option | Default | Description |
|--------|---------|-------------|
| `aggregation_enabled` | `true` | Enable connection aggregation to reduce event volume |
| `aggregation_max_entries` | `20000` | Maximum unique connections to track |
| `aggregation_interval_buffer_size` | `50` | Intervals to store for beacon detection |

Connection aggregation suppresses repeated connections from the same process to the same destination,
emitting only the first connection. Timing data is collected for future beacon detection analysis.

## Environment Variables

Override any setting using the `EDR__` prefix with double underscore separators:

```powershell
$env:EDR__LOGGING__LEVEL="debug"
$env:EDR__SCANNER__SIGMA_RULES_PATH="C:\\custom\\sigma"
$env:EDR__SCANNER__YARA_RULES_PATH="C:\\custom\\yara"

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
