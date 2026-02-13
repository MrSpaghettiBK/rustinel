# Rustinel Documentation

Rustinel is a high-performance, user-mode Windows EDR agent written in Rust. It collects
kernel telemetry via ETW, normalizes to Sysmon-style fields, runs Sigma, YARA, and
atomic IOC detection, and writes ECS 9.3.0 NDJSON alerts (non-ECS fields use the `edr.` prefix).

## Start Here

- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [CLI Reference](cli.md)

## Guides

- [Detection (Sigma + YARA + IOC)](detection.md)
- [Active Response](active-response.md)
- [Output Format](output.md)

## Reference

- [Architecture](architecture.md)
- [Development](development.md)
- [Roadmap](roadmap.md)

## Quick Start (60 seconds)

1. Download the latest release from GitHub Releases.
2. Open an elevated PowerShell in the extracted folder.
3. Run `.\rustinel.exe run --console`.
4. Verify output in `logs/rustinel.log.YYYY-MM-DD` and `logs/alerts.json.YYYY-MM-DD`.

## Notes

- Windows only. Administrator privileges are required for ETW.
- Configuration and rules are resolved from the current working directory. For service mode, use absolute paths or environment overrides.
- Service mode is supported on Windows. See the CLI Reference for commands.
- Trusted path allowlisting is shared by default across Response, IOC hash, and YARA (`allowlist.paths`).
