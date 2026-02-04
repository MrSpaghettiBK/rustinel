# Output Format

Rustinel produces two types of output: operational logs and security alerts.

## Operational Logs

**Location:** `logs/rustinel.log.YYYY-MM-DD`

**Format:** Plain text with timestamps

**Rotation:** Daily

**Content:**
- Startup/shutdown messages
- Detection triggers
- Errors and warnings
- Debug information (if enabled)
- Active response actions (dry-run or termination)

**Example:**

```
2025-01-15T14:32:10Z INFO  rustinel: Starting Rustinel EDR agent
2025-01-15T14:32:10Z INFO  collector: Registered 9 ETW providers
2025-01-15T14:32:10Z INFO  engine: Loaded 42 Sigma rules
2025-01-15T14:32:15Z INFO  engine: Detection: Whoami Execution
2025-01-15T14:32:16Z INFO  response: Active response would terminate process pid=4242 image="C:\\Temp\\evil.exe" dry_run=true
```

## Security Alerts

**Location:** `logs/alerts.json.YYYY-MM-DD`

**Format:** ECS NDJSON (one JSON object per line)

**Rotation:** Daily

### Alert Structure

```json
{
  "@timestamp": "2025-01-15T14:32:10Z",
  "event.kind": "alert",
  "event.category": "process",
  "rule.name": "Whoami Execution",
  "rule.severity": "Low",
  "rule.engine": "Sigma",
  "process.executable": "C:\\Windows\\System32\\whoami.exe",
  "process.command_line": "whoami /all",
  "process.pid": "1234",
  "process.parent.executable": "C:\\Windows\\System32\\cmd.exe",
  "process.parent.pid": "5678",
  "user.name": "DOMAIN\\username"
}
```

### ECS Fields

**Core:**
- `@timestamp` - Event time (ISO 8601 UTC)
- `event.kind` - Always `alert`
- `event.category` - One of: `process`, `network`, `file`, `registry`, `dns`, `imageload`, `scripting`, `wmi`, `service`, `task`, `pipeevent`

**Rule:**
- `rule.name` - Detection rule name
- `rule.severity` - `Low`, `Medium`, `High`, or `Critical`
- `rule.engine` - `Sigma` or `Yara`

**Process Context:**
- `process.executable`, `process.command_line`, `process.pid`
- `process.parent.executable`, `process.parent.command_line`, `process.parent.pid`
- `process.working_directory`, `process.integrity_level`
- `process.pe.original_file_name`, `process.pe.product`, `process.pe.description`
- `user.name`, `winlog.logon.id`, `winlog.logon.guid`

**Network Context:**
- `destination.ip`, `destination.port`
- `source.ip`, `source.port`
- `destination.domain`

**File Context:**
- `file.path`, `file.created`
- `file.pe.original_file_name`, `file.pe.product`, `file.pe.description`

**Registry Context:**
- `registry.path`, `registry.value`

**Service and Task Context:**
- `service.name`, `service.executable`

**DNS Context:**
- `dns.question.name`

**Pipe Context:**
- `pipe.name`

### EDR Extensions

Fields not covered by ECS are emitted with the `edr.` prefix. Examples:

- `edr.file.previous_created`, `edr.file.signed`, `edr.file.signature`
- `edr.registry.event_type`, `edr.registry.new_name`
- `edr.dns.answers`, `edr.dns.response_code`
- `edr.service.type`, `edr.service.start_type`, `edr.service.account_name`
- `edr.task.content`, `edr.task.user_name`
- `edr.pipe.event_type`
- `edr.powershell.script_block_text`, `edr.powershell.script_block_id`
- `edr.wmi.operation`, `edr.wmi.query`, `edr.wmi.namespace`, `edr.wmi.event_type`
- `edr.remote_thread.target_pid`, `edr.remote_thread.target_image`
- `edr.process.target_image`

## SIEM Integration

Alerts are designed for direct ingestion into:
- Elasticsearch or OpenSearch
- Splunk
- Any SIEM supporting ECS or NDJSON

**Example Filebeat config:**

```yaml
filebeat.inputs:
- type: log
  paths:
    - C:\\Rustinel\\logs\\alerts.json.*
  json.keys_under_root: true
```
