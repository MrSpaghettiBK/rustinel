# Active Response

Rustinel includes an optional active response engine that can terminate processes
when a **critical** alert is raised. It is disabled by default and can run in
dry-run mode to validate behavior safely.

## Modes

The response engine has three states:

1. Disabled: no actions are queued.
2. Dry-run: actions are logged but no process is terminated.
3. Prevention: eligible processes are terminated.

## Severity Handling

- **Sigma**: severity comes from the rule `level` (`low`, `medium`, `high`, `critical`).
- **YARA**: all matches are treated as `critical`.

The `min_severity` gate applies after this mapping.
Unknown `min_severity` values default to `critical` and a warning is logged.

## Allowlists

Allowlists prevent termination of trusted processes:

- `allowlist_images`: basenames (e.g. `cmd.exe`) or full paths.
- `allowlist_paths`: path prefixes (case-insensitive).

Defaults include:
`C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`.

## Configuration

```toml
[response]
enabled = true
prevention_enabled = false
min_severity = "critical"
channel_capacity = 128
allowlist_images = []
allowlist_paths = [
  "C:\\Windows\\",
  "C:\\Program Files\\",
  "C:\\Program Files (x86)\\",
]
```

## Logging

Actions are logged under the `response` target in the operational log:

```
response: Active response would terminate process pid=4242 image="C:\Temp\evil.exe" dry_run=true
response: Active response terminated process pid=4242 image="C:\Temp\evil.exe"
response: Active response skipped: allowlisted pid=4321 image="C:\Windows\System32\cmd.exe"
```

## Safety Checks

The response engine will skip termination if:

- PID is missing
- PID is `0..4` (system processes)
- PID is the agent’s own process
- Image/path is allowlisted

## Quick Test

### Option 1: YARA Demo (Recommended)

The built-in YARA demo provides the easiest way to test active response:

1. Build the demo binary:
   ```powershell
   rustc .\examples\yara_demo.rs -o .\examples\yara_demo.exe
   ```

2. Enable response in `config.toml`:
   ```toml
   [response]
   enabled = true
   prevention_enabled = false  # Start with dry-run
   ```

3. Run Rustinel and the demo:
   ```powershell
   # Terminal 1: Start Rustinel
   cargo run -- run --console

   # Terminal 2: Run the demo
   .\examples\yara_demo.exe
   ```

4. Check logs for dry-run message:
   ```
   response: Active response would terminate process pid=XXXX image="...\yara_demo.exe" dry_run=true
   ```

5. Enable prevention and re-test:
   ```toml
   prevention_enabled = true  # Enable termination
   ```
   The demo process should be terminated within seconds of starting.

### Option 2: Custom Sigma Rule

1. Copy a safe process to a non-allowlisted path:
   ```powershell
   New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
   Copy-Item C:\Windows\System32\ping.exe C:\Temp\ping-test.exe
   ```

2. Add a critical Sigma rule:
   ```yaml
   title: Local Response Test (Ping)
   logsource:
     product: windows
     category: process_creation
   detection:
     selection:
       Image|endswith: 'ping-test.exe'
     condition: selection
   level: critical
   ```

3. Run the process:
   ```powershell
   C:\Temp\ping-test.exe 127.0.0.1 -t
   ```

With `prevention_enabled = false`, it will log the action.
With `prevention_enabled = true`, the process should be terminated quickly.
