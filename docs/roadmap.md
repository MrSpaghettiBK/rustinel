# Roadmap

Short roadmap:

- YARA expansion (memory scanning + periodic scans).
- Resource governor (Windows Job Objects CPU limits).
- Self-defense hardening (DACL/ACL restrictions + anti-injection).
- Watchdog sidecar to restart the service if the main process dies.
- ETW integrity checks to detect blinding/tampering.
- Deep inspection via stack tracing for "floating code".

Completed:
- Active response engine (optional prevention mode, terminate on critical alerts).
