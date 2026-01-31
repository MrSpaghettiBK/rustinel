//! ECS (Elastic Common Schema) alert mapping
//!
//! This module provides a translation layer between internal Alert structures
//! and the standardized ECS format expected by SIEM systems like Elasticsearch,
//! Splunk, and other log aggregation platforms.
//!
//! ## Design
//! - Decouples internal data models from external API contracts
//! - Ensures consistent JSON output for security alerts
//! - Supports incremental field additions without breaking changes

use crate::models::{Alert, EventFields, ProcessContext};
use serde::Serialize;

/// ECS-compliant alert structure for SIEM ingestion
#[derive(Serialize)]
pub struct EcsAlert {
    /// Event timestamp in ISO 8601 format
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    /// Event kind (always "alert" for detections)
    #[serde(rename = "event.kind")]
    pub event_kind: String,

    /// Event category for classification
    #[serde(rename = "event.category", skip_serializing_if = "Option::is_none")]
    pub event_category: Option<String>,

    /// Detection rule name
    #[serde(rename = "rule.name")]
    pub rule_name: String,

    /// Detection severity (critical, high, medium, low)
    #[serde(rename = "rule.severity")]
    pub severity: String,

    /// Detection engine (Sigma, Yara)
    #[serde(rename = "rule.engine")]
    pub engine: String,

    // ========================================================================
    // Process Fields
    // ========================================================================
    #[serde(rename = "process.executable", skip_serializing_if = "Option::is_none")]
    pub process_executable: Option<String>,

    #[serde(
        rename = "process.command_line",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_command_line: Option<String>,

    #[serde(rename = "process.pid", skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<String>,

    #[serde(
        rename = "process.parent.executable",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_parent_executable: Option<String>,

    #[serde(
        rename = "process.parent.command_line",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_parent_command_line: Option<String>,

    #[serde(rename = "process.parent.pid", skip_serializing_if = "Option::is_none")]
    pub process_parent_pid: Option<String>,

    #[serde(
        rename = "process.working_directory",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_working_directory: Option<String>,

    #[serde(
        rename = "process.integrity_level",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_integrity_level: Option<String>,

    #[serde(
        rename = "process.pe.original_file_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_original_file_name: Option<String>,

    #[serde(rename = "process.pe.product", skip_serializing_if = "Option::is_none")]
    pub process_product: Option<String>,

    #[serde(
        rename = "process.pe.description",
        skip_serializing_if = "Option::is_none"
    )]
    pub process_description: Option<String>,

    #[serde(rename = "user.name", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    #[serde(rename = "winlog.logon.id", skip_serializing_if = "Option::is_none")]
    pub winlog_logon_id: Option<String>,

    #[serde(rename = "winlog.logon.guid", skip_serializing_if = "Option::is_none")]
    pub winlog_logon_guid: Option<String>,

    // ========================================================================
    // Network Fields
    // ========================================================================
    #[serde(rename = "destination.ip", skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,

    #[serde(rename = "destination.port", skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<String>,

    #[serde(rename = "source.ip", skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    #[serde(rename = "source.port", skip_serializing_if = "Option::is_none")]
    pub source_port: Option<String>,

    #[serde(rename = "destination.domain", skip_serializing_if = "Option::is_none")]
    pub destination_domain: Option<String>,

    // ========================================================================
    // File Fields
    // ========================================================================
    #[serde(rename = "file.path", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    #[serde(rename = "file.created", skip_serializing_if = "Option::is_none")]
    pub file_created: Option<String>,

    #[serde(
        rename = "edr.file.previous_created",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_file_previous_created: Option<String>,

    #[serde(
        rename = "file.pe.original_file_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_original_file_name: Option<String>,

    #[serde(rename = "file.pe.product", skip_serializing_if = "Option::is_none")]
    pub file_product: Option<String>,

    #[serde(
        rename = "file.pe.description",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_description: Option<String>,

    #[serde(rename = "edr.file.signed", skip_serializing_if = "Option::is_none")]
    pub edr_file_signed: Option<String>,

    #[serde(rename = "edr.file.signature", skip_serializing_if = "Option::is_none")]
    pub edr_file_signature: Option<String>,

    // ========================================================================
    // Registry Fields
    // ========================================================================
    #[serde(rename = "registry.path", skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,

    #[serde(rename = "registry.value", skip_serializing_if = "Option::is_none")]
    pub registry_value: Option<String>,

    #[serde(
        rename = "edr.registry.event_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_registry_event_type: Option<String>,

    #[serde(
        rename = "edr.registry.new_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_registry_new_name: Option<String>,

    // ========================================================================
    // DNS Fields
    // ========================================================================
    #[serde(rename = "dns.question.name", skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,

    #[serde(rename = "edr.dns.answers", skip_serializing_if = "Option::is_none")]
    pub edr_dns_answers: Option<String>,

    #[serde(
        rename = "edr.dns.response_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_dns_response_code: Option<String>,

    // ========================================================================
    // Service Persistence Fields
    // ========================================================================
    #[serde(rename = "service.name", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    #[serde(rename = "service.executable", skip_serializing_if = "Option::is_none")]
    pub service_executable: Option<String>,

    #[serde(rename = "edr.service.type", skip_serializing_if = "Option::is_none")]
    pub edr_service_type: Option<String>,

    #[serde(
        rename = "edr.service.start_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_service_start_type: Option<String>,

    #[serde(
        rename = "edr.service.account_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_service_account_name: Option<String>,

    // ========================================================================
    // Task Scheduler Persistence Fields
    // ========================================================================
    #[serde(rename = "task.name", skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,

    #[serde(rename = "edr.task.content", skip_serializing_if = "Option::is_none")]
    pub edr_task_content: Option<String>,

    #[serde(rename = "edr.task.user_name", skip_serializing_if = "Option::is_none")]
    pub edr_task_user_name: Option<String>,

    // ========================================================================
    // Named Pipe (Lateral Movement) Fields
    // ========================================================================
    #[serde(rename = "pipe.name", skip_serializing_if = "Option::is_none")]
    pub pipe_name: Option<String>,

    #[serde(
        rename = "edr.pipe.event_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_pipe_event_type: Option<String>,

    // ========================================================================
    // PowerShell Fields
    // ========================================================================
    #[serde(
        rename = "edr.powershell.script_block_text",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_powershell_script_block_text: Option<String>,

    #[serde(
        rename = "edr.powershell.script_block_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_powershell_script_block_id: Option<String>,

    // ========================================================================
    // WMI Fields
    // ========================================================================
    #[serde(rename = "edr.wmi.operation", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_operation: Option<String>,

    #[serde(rename = "edr.wmi.query", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_query: Option<String>,

    #[serde(rename = "edr.wmi.namespace", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_namespace: Option<String>,

    #[serde(rename = "edr.wmi.event_type", skip_serializing_if = "Option::is_none")]
    pub edr_wmi_event_type: Option<String>,

    // ========================================================================
    // Remote Thread Fields
    // ========================================================================
    #[serde(
        rename = "edr.remote_thread.target_pid",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_target_pid: Option<String>,

    #[serde(
        rename = "edr.remote_thread.target_image",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_target_image: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_address",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_address: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_module",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_module: Option<String>,

    #[serde(
        rename = "edr.remote_thread.start_function",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_remote_thread_start_function: Option<String>,

    // ========================================================================
    // Process Target Fields
    // ========================================================================
    #[serde(
        rename = "edr.process.target_image",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_process_target_image: Option<String>,
}

/// Convert internal Alert to ECS format
impl From<&Alert> for EcsAlert {
    fn from(alert: &Alert) -> Self {
        let mut ecs = EcsAlert {
            timestamp: alert.event.timestamp.clone(),
            event_kind: "alert".to_string(),
            event_category: Some(format!("{:?}", alert.event.category).to_lowercase()),
            rule_name: alert.rule_name.clone(),
            severity: format!("{:?}", alert.severity),
            engine: format!("{:?}", alert.engine),
            process_executable: None,
            process_command_line: None,
            process_pid: None,
            process_parent_executable: None,
            process_parent_command_line: None,
            process_parent_pid: None,
            process_working_directory: None,
            process_integrity_level: None,
            process_original_file_name: None,
            process_product: None,
            process_description: None,
            user_name: None,
            winlog_logon_id: None,
            winlog_logon_guid: None,
            destination_ip: None,
            destination_port: None,
            source_ip: None,
            source_port: None,
            destination_domain: None,
            file_path: None,
            file_created: None,
            edr_file_previous_created: None,
            file_original_file_name: None,
            file_product: None,
            file_description: None,
            edr_file_signed: None,
            edr_file_signature: None,
            registry_path: None,
            registry_value: None,
            edr_registry_event_type: None,
            edr_registry_new_name: None,
            dns_query: None,
            edr_dns_answers: None,
            edr_dns_response_code: None,
            service_name: None,
            service_executable: None,
            edr_service_type: None,
            edr_service_start_type: None,
            edr_service_account_name: None,
            task_name: None,
            edr_task_content: None,
            edr_task_user_name: None,
            pipe_name: None,
            edr_pipe_event_type: None,
            edr_powershell_script_block_text: None,
            edr_powershell_script_block_id: None,
            edr_wmi_operation: None,
            edr_wmi_query: None,
            edr_wmi_namespace: None,
            edr_wmi_event_type: None,
            edr_remote_thread_target_pid: None,
            edr_remote_thread_target_image: None,
            edr_remote_thread_start_address: None,
            edr_remote_thread_start_module: None,
            edr_remote_thread_start_function: None,
            edr_process_target_image: None,
        };

        // Map internal fields to ECS based on event type
        match &alert.event.fields {
            EventFields::ProcessCreation(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_command_line = f.command_line.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.process_parent_executable = f.parent_image.clone();
                ecs.process_parent_command_line = f.parent_command_line.clone();
                ecs.process_parent_pid = f.parent_process_id.clone();
                ecs.process_working_directory = f.current_directory.clone();
                ecs.process_integrity_level = f.integrity_level.clone();
                ecs.process_original_file_name = f.original_file_name.clone();
                ecs.process_product = f.product.clone();
                ecs.process_description = f.description.clone();
                ecs.user_name = f.user.clone();
                ecs.winlog_logon_id = f.logon_id.clone();
                ecs.winlog_logon_guid = f.logon_guid.clone();
                ecs.edr_process_target_image = f.target_image.clone();
            }
            EventFields::NetworkConnection(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.destination_ip = f.destination_ip.clone();
                ecs.destination_port = f.destination_port.clone();
                ecs.source_ip = f.source_ip.clone();
                ecs.source_port = f.source_port.clone();
                ecs.destination_domain = f.destination_hostname.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::FileEvent(f) => {
                ecs.file_path = f.target_filename.clone();
                ecs.file_created = f.creation_utc_time.clone();
                ecs.edr_file_previous_created = f.previous_creation_utc_time.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::RegistryEvent(f) => {
                ecs.registry_path = f.target_object.clone();
                ecs.registry_value = f.details.clone();
                ecs.edr_registry_event_type = f.event_type.clone();
                ecs.edr_registry_new_name = f.new_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::DnsQuery(f) => {
                ecs.dns_query = f.query_name.clone();
                ecs.edr_dns_answers = f.query_results.clone();
                ecs.edr_dns_response_code = f.query_status.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
            }
            EventFields::ImageLoad(f) => {
                ecs.file_path = f.image_loaded.clone();
                ecs.file_original_file_name = f.original_file_name.clone();
                ecs.file_product = f.product.clone();
                ecs.file_description = f.description.clone();
                ecs.edr_file_signed = f.signed.clone();
                ecs.edr_file_signature = f.signature.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::PowerShellScript(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
                ecs.file_path = f.path.clone();
                ecs.edr_powershell_script_block_text = f.script_block_text.clone();
                ecs.edr_powershell_script_block_id = f.script_block_id.clone();
            }
            EventFields::WmiEvent(f) => {
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
                ecs.destination_domain = f.destination_hostname.clone();
                ecs.edr_wmi_operation = f.operation.clone();
                ecs.edr_wmi_query = f.query.clone();
                ecs.edr_wmi_namespace = f.event_namespace.clone();
                ecs.edr_wmi_event_type = f.event_type.clone();
            }
            EventFields::ServiceCreation(f) => {
                ecs.service_name = f.service_name.clone();
                ecs.service_executable = f.service_file_name.clone();
                ecs.edr_service_type = f.service_type.clone();
                ecs.edr_service_start_type = f.start_type.clone();
                ecs.edr_service_account_name = f.account_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::TaskCreation(f) => {
                ecs.task_name = f.task_name.clone();
                ecs.edr_task_content = f.task_content.clone();
                ecs.edr_task_user_name = f.user_name.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::PipeEvent(f) => {
                ecs.pipe_name = f.pipe_name.clone();
                ecs.edr_pipe_event_type = f.event_type.clone();
                ecs.process_executable = f.image.clone();
                ecs.process_pid = f.process_id.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::RemoteThread(f) => {
                ecs.process_executable = f.source_image.clone();
                ecs.process_pid = f.source_process_id.clone();
                ecs.edr_remote_thread_target_pid = f.target_process_id.clone();
                ecs.edr_remote_thread_target_image = f.target_image.clone();
                ecs.edr_remote_thread_start_address = f.start_address.clone();
                ecs.edr_remote_thread_start_module = f.start_module.clone();
                ecs.edr_remote_thread_start_function = f.start_function.clone();
                ecs.user_name = f.user.clone();
            }
            EventFields::Generic(_) => {
                // Generic events don't have structured field mapping
            }
        }

        if let Some(context) = &alert.event.process_context {
            Self::apply_process_context(&mut ecs, context);
        }

        ecs
    }
}

impl EcsAlert {
    fn apply_process_context(ecs: &mut EcsAlert, context: &ProcessContext) {
        if ecs.process_executable.is_none() {
            ecs.process_executable = context.image.clone();
        }
        if ecs.process_command_line.is_none() {
            ecs.process_command_line = context.command_line.clone();
        }
        if ecs.process_pid.is_none() {
            ecs.process_pid = context.process_id.clone();
        }
        if ecs.process_parent_executable.is_none() {
            ecs.process_parent_executable = context.parent_image.clone();
        }
        if ecs.process_parent_command_line.is_none() {
            ecs.process_parent_command_line = context.parent_command_line.clone();
        }
        if ecs.process_parent_pid.is_none() {
            ecs.process_parent_pid = context.parent_process_id.clone();
        }
        if ecs.process_working_directory.is_none() {
            ecs.process_working_directory = context.current_directory.clone();
        }
        if ecs.process_integrity_level.is_none() {
            ecs.process_integrity_level = context.integrity_level.clone();
        }
        if ecs.process_original_file_name.is_none() {
            ecs.process_original_file_name = context.original_file_name.clone();
        }
        if ecs.process_product.is_none() {
            ecs.process_product = context.product.clone();
        }
        if ecs.process_description.is_none() {
            ecs.process_description = context.description.clone();
        }
        if ecs.user_name.is_none()
            || (matches!(ecs.user_name.as_deref(), Some(value) if value.starts_with("S-1-"))
                && context.user.is_some())
        {
            ecs.user_name = context.user.clone();
        }
        if ecs.winlog_logon_id.is_none() {
            ecs.winlog_logon_id = context.logon_id.clone();
        }
        if ecs.winlog_logon_guid.is_none() {
            ecs.winlog_logon_guid = context.logon_guid.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertSeverity, DetectionEngine, EventCategory, NormalizedEvent, ProcessContext,
        ProcessCreationFields, ServiceCreationFields,
    };

    #[test]
    fn test_ecs_process_creation() {
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Test Rule".to_string(),
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                    command_line: Some("cmd.exe /c whoami".to_string()),
                    process_id: Some("1234".to_string()),
                    parent_image: Some("C:\\Windows\\explorer.exe".to_string()),
                    user: Some("SYSTEM".to_string()),
                    original_file_name: None,
                    product: None,
                    description: None,
                    target_image: None,
                    parent_process_id: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    logon_id: None,
                    logon_guid: None,
                }),
                process_context: None,
            },
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.event_kind, "alert");
        assert_eq!(ecs.rule_name, "Test Rule");
        assert_eq!(ecs.severity, "High");
        assert!(ecs.process_executable.is_some());
        assert!(ecs.process_command_line.is_some());
    }

    #[test]
    fn test_ecs_service_creation() {
        let alert = Alert {
            severity: AlertSeverity::Critical,
            rule_name: "Suspicious Service".to_string(),
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Service,
                event_id: 7045,
                event_id_string: "7045".to_string(),
                opcode: 0,
                fields: EventFields::ServiceCreation(ServiceCreationFields {
                    service_name: Some("BackdoorSvc".to_string()),
                    service_file_name: Some("C:\\Temp\\evil.exe".to_string()),
                    service_type: Some("0x10".to_string()),
                    start_type: Some("2".to_string()),
                    account_name: Some("LocalSystem".to_string()),
                    user: Some("Administrator".to_string()),
                    process_id: None,
                    image: None,
                }),
                process_context: None,
            },
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(ecs.service_name, Some("BackdoorSvc".to_string()));
        assert_eq!(
            ecs.service_executable,
            Some("C:\\Temp\\evil.exe".to_string())
        );
        assert_eq!(ecs.severity, "Critical");
    }

    #[test]
    fn test_ecs_process_context_fallback() {
        let alert = Alert {
            severity: AlertSeverity::High,
            rule_name: "Context Test".to_string(),
            engine: DetectionEngine::Sigma,
            event: NormalizedEvent {
                timestamp: "2026-01-06T00:00:00Z".to_string(),
                category: EventCategory::Service,
                event_id: 7045,
                event_id_string: "7045".to_string(),
                opcode: 0,
                fields: EventFields::ServiceCreation(ServiceCreationFields {
                    service_name: Some("UpdaterSvc".to_string()),
                    service_file_name: Some("C:\\Temp\\updater.exe".to_string()),
                    service_type: None,
                    start_type: None,
                    account_name: None,
                    user: None,
                    process_id: None,
                    image: None,
                }),
                process_context: Some(ProcessContext {
                    image: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
                    command_line: Some("svchost.exe -k netsvcs".to_string()),
                    process_id: Some("4321".to_string()),
                    parent_process_id: Some("100".to_string()),
                    parent_image: Some("C:\\Windows\\System32\\services.exe".to_string()),
                    parent_command_line: Some("services.exe".to_string()),
                    original_file_name: Some("svchost.exe".to_string()),
                    product: Some("Microsoft Windows".to_string()),
                    description: Some("Host Process".to_string()),
                    current_directory: Some("C:\\Windows\\System32".to_string()),
                    integrity_level: Some("System".to_string()),
                    user: Some("NT AUTHORITY\\SYSTEM".to_string()),
                    logon_id: Some("0x3e7".to_string()),
                    logon_guid: Some("guid".to_string()),
                }),
            },
        };

        let ecs = EcsAlert::from(&alert);
        assert_eq!(
            ecs.process_command_line,
            Some("svchost.exe -k netsvcs".to_string())
        );
        assert_eq!(
            ecs.process_parent_executable,
            Some("C:\\Windows\\System32\\services.exe".to_string())
        );
        assert_eq!(
            ecs.process_original_file_name,
            Some("svchost.exe".to_string())
        );
        assert_eq!(ecs.winlog_logon_id, Some("0x3e7".to_string()));
    }
}
