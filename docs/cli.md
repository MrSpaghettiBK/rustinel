# CLI Reference

## Usage

```
rustinel [COMMAND] [OPTIONS]
```

## Global Options

- `--log-level <LEVEL>` - Override logging level for this run (`trace`, `debug`, `info`, `warn`, `error`). This is applied only to `run` and is ignored by service commands.

## Commands

### run

Run in console mode with visible output.

```
rustinel run [--console] [--log-level <LEVEL>]
```

**Options:**
- `--console` - Force console output regardless of config

**Examples:**

```powershell
rustinel run
rustinel run --console
rustinel run --log-level debug
```

### service

Manage Windows service installation and lifecycle.

```
rustinel service <install|uninstall|start|stop>
```

Service commands require an elevated PowerShell.

**Examples:**

```powershell
rustinel service install
rustinel service start
rustinel service stop
rustinel service uninstall
```

## Default Behavior

Running `rustinel` without arguments is equivalent to `rustinel run`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (check logs for details) |

## Environment Variables

Configuration can be overridden via environment variables using the `EDR__` prefix and double underscore separators.

```powershell
$env:EDR__LOGGING__LEVEL="debug"
$env:EDR__SCANNER__SIGMA_ENABLED="true"
rustinel run
```

To clear a variable for the current shell:

```powershell
Remove-Item Env:EDR__LOGGING__LEVEL
```

See [Configuration](configuration.md) for all available options.
