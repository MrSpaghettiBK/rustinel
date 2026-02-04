# Detection

Rustinel uses two detection engines: Sigma for behavioral rules and YARA for file scanning.

## Sigma Rules

### Logsource Categories (Required)

Rustinel routes rules by `logsource.category`. The `product` and `service` fields
are parsed but not used for routing. If `category` is missing, the rule is
categorized as `unknown` and will not match events.

Supported categories:

- `process_creation`
- `network_connection`
- `file_event`
- `file_create`
- `file_delete`
- `registry_event`
- `registry_add`
- `registry_set`
- `registry_delete`
- `dns_query`
- `image_load`
- `ps_script`
- `wmi_event`
- `service_creation`
- `task_creation`
- `pipe_created`

### Rule Format

```yaml
title: Suspicious Process
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\suspicious.exe'
  filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
level: high
```

### Detection Logic

- Boolean operators: `and`, `or`, `not`
- Parentheses for grouping
- Aggregation: `1 of selection*`, `all of them`

### Supported Modifiers

| Modifier | Meaning |
|----------|---------|
| `contains` | Substring match |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `all` | All values must match |
| `cased` | Case-sensitive match |
| `re` | Regular expression |
| `i`, `m`, `s` | Regex flags for `re` (case-insensitive, multiline, dotall) |
| `windash` | Windows dash normalization (`-` and `/`) |
| `fieldref` | Reference another field in the same event |
| `exists` | Field presence check |
| `cidr` | IP range matching |
| `base64` | Base64-encoded matching |
| `base64offset` | Base64 with offset variations |
| `wide`, `utf16`, `utf16le`, `utf16be` | UTF-16 transformations |
| `lt`, `gt`, `le`, `lte`, `ge`, `gte` | Numeric comparison |

Wildcard characters `*` and `?` are supported in string patterns.

### Common Fields

Process events:

- `Image`, `CommandLine`, `User`, `ParentImage`, `ParentCommandLine`
- `OriginalFileName`, `Product`, `Description`
- `ProcessId`, `ParentProcessId`, `IntegrityLevel`, `CurrentDirectory`
- `TargetImage`, `LogonId`, `LogonGuid`

Network events:

- `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`
- `DestinationHostname`, `Image`, `ProcessId`, `User`

File events:

- `TargetFilename`, `Image`, `ProcessId`, `User`
- `CreationUtcTime`, `PreviousCreationUtcTime`

Registry events:

- `TargetObject`, `Details`, `EventType`, `NewName`
- `Image`, `ProcessId`, `User`

DNS events:

- `QueryName`, `QueryResults`, `QueryStatus`
- `Image`, `ProcessId`

Image load events:

- `ImageLoaded`, `Image`, `OriginalFileName`, `Product`, `Description`
- `Signed`, `Signature`, `User`, `ProcessId`

PowerShell script events:

- `ScriptBlockText`, `ScriptBlockId`, `Path`
- `Image`, `ProcessId`, `User`

WMI events:

- `Operation`, `Query`, `EventNamespace`, `EventType`
- `DestinationHostname`, `Image`, `ProcessId`, `User`

Service creation events:

- `ServiceName`, `ServiceFileName`, `ServiceType`, `StartType`, `AccountName`
- `Image`, `ProcessId`, `User`

Task creation events:

- `TaskName`, `TaskContent`, `UserName`
- `Image`, `ProcessId`, `User`

Named pipe events:

- `PipeName`, `EventType`, `Image`, `ProcessId`, `User`

## YARA Rules

### Rule Format

```yara
rule ExampleDetection {
  meta:
    description = "Detects example malware"
    severity = "high"

  strings:
    $s1 = "malicious_string" nocase
    $s2 = { 4D 5A 90 00 }

  condition:
    $s1 or $s2
}
```

### Behavior

- Rules loaded from `rules/yara/` at startup
- Scans triggered on process creation events
- File scanning runs in background (non-blocking)
- Matches generate alerts with the rule name

### Supported Rule Files

- `.yar`
- `.yara`

## Severity Levels

Sigma `level` values map to alert severity as follows:

- `critical` -> Critical
- `high` -> High
- `medium` -> Medium
- Any other value -> Low

YARA matches are always treated as Critical.
