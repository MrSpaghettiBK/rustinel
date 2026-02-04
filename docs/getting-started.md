# Getting Started

This guide gets Rustinel running and verifies it is producing alerts.

## Requirements

- Windows 10/11 or Server 2016+
- Administrator privileges
- Rust 1.92+ and Visual Studio Build Tools if building from source

## Option 1: Download Release (Recommended)

1. Download the latest release from GitHub Releases.
2. Extract the archive to a folder such as `C:\Rustinel`.
3. Open an elevated PowerShell in that folder.
4. Run `.\rustinel.exe run --console`.

## Option 2: Build from Source

```powershell
git clone https://github.com/Karib0u/rustinel.git
cd rustinel
cargo run -- run --console
```

For an optimized binary:

```powershell
cargo build --release
.\target\release\rustinel.exe run --console
```

## Verify Operation

1. Confirm the log file exists: `logs\rustinel.log.YYYY-MM-DD`.
2. Trigger a Sigma example by running `whoami /all`.
3. Confirm an alert exists in `logs\alerts.json.YYYY-MM-DD`.

## Run as a Service (Optional)

Service commands must be run from the final install directory. The service uses
its working directory to resolve `config.toml` and relative rule paths, so prefer
absolute paths in configuration for service deployments.

```powershell
.\rustinel.exe service install
.\rustinel.exe service start
.\rustinel.exe service stop
.\rustinel.exe service uninstall
```

## Troubleshooting

- If you see an Administrator privilege error, reopen PowerShell as Administrator.
- If no alerts are produced, confirm rules exist under `rules\sigma` or `rules\yara`.
