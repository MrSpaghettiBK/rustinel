//! Sigma detection event handler
//!
//! Implements the EventHandler trait to process ETW events
//! through the Sigma detection engine.

use crate::alerts::AlertSink;
use crate::collector::EventHandler;
use crate::engine::Engine;
use crate::ioc::IocEngine;
use crate::models::EventCategory;
use crate::normalizer::Normalizer;
use crate::response::ResponseEngine;
use ferrisetw::EventRecord;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Target name for engine operational logs
const TARGET_ENGINE: &str = "engine";

/// Sigma detection handler that normalizes events and checks them against Sigma rules
pub struct SigmaDetectionHandler {
    /// Normalizer for converting ETW events to Sysmon-compatible format
    pub normalizer: Arc<Normalizer>,
    /// Sigma detection engine
    pub engine: Arc<Engine>,
    /// IOC detection engine (optional)
    pub ioc_engine: Option<Arc<IocEngine>>,
    /// Hash worker channel (optional)
    pub ioc_hash_tx: Option<mpsc::Sender<(String, u32)>>,
    /// ECS NDJSON alert sink
    pub alert_sink: AlertSink,
    /// Active response engine
    pub response_engine: ResponseEngine,
}

impl EventHandler for SigmaDetectionHandler {
    fn handle_event(&self, record: &EventRecord, category: EventCategory) {
        // Trace-level event receipt log for deep pipeline diagnostics.
        tracing::trace!(
            target: TARGET_ENGINE,
            category = ?category,
            provider = ?record.provider_id(),
            event_id = record.event_id(),
            opcode = record.opcode(),
            "Event received"
        );

        // Normalize the event
        match self.normalizer.normalize(record, category) {
            Some(normalized_event) => {
                tracing::trace!(target: TARGET_ENGINE, "Event normalized successfully");

                // Trace normalized event only when trace logging is enabled.
                if tracing::enabled!(tracing::Level::TRACE) {
                    if let Ok(json) = serde_json::to_string(&normalized_event) {
                        tracing::trace!(target: TARGET_ENGINE, normalized_json = %json, "Normalized event");
                    }
                }

                // Queue hash checks on process start (non-blocking)
                if let Some(tx) = &self.ioc_hash_tx {
                    if normalized_event.category == EventCategory::Process
                        && normalized_event.opcode == 1
                    {
                        if let crate::models::EventFields::ProcessCreation(f) =
                            &normalized_event.fields
                        {
                            if let Some(image) = &f.image {
                                let pid = f
                                    .process_id
                                    .as_deref()
                                    .and_then(|value| value.parse::<u32>().ok())
                                    .unwrap_or_else(|| record.process_id());
                                if let Err(err) = tx.try_send((image.clone(), pid)) {
                                    debug!(
                                        target: TARGET_ENGINE,
                                        pid = pid,
                                        image = %image,
                                        error = %err,
                                        "IOC hash queue full; dropping job"
                                    );
                                }
                            }
                        }
                    }
                }

                // Check against Sigma rules
                if let Some(mut alert) = self.engine.check_event(&normalized_event) {
                    self.normalizer
                        .enrich_process_context(&mut alert.event, record.process_id());

                    // 1. Operational Log (Text) - For debugging and monitoring
                    info!(
                        target: TARGET_ENGINE,
                        rule = %alert.rule_name,
                        severity = ?alert.severity,
                        category = ?alert.event.category,
                        "Sigma detection triggered"
                    );

                    // 2. Security Alert (ECS NDJSON) - For SIEM ingestion
                    self.alert_sink.write_alert(&alert);

                    // 3. Active Response (optional)
                    self.response_engine.handle_alert(&alert);
                } else {
                    // No match - moved to TRACE level (most verbose)
                    tracing::trace!(target: TARGET_ENGINE, "No Sigma rule matched this event");
                }

                // Check against IOC rules
                if let Some(ioc_engine) = &self.ioc_engine {
                    let ioc_matches = ioc_engine.check_event(&normalized_event);
                    if !ioc_matches.is_empty() {
                        for m in ioc_matches {
                            let mut alert = ioc_engine.build_alert_for_match(&m, &normalized_event);
                            self.normalizer
                                .enrich_process_context(&mut alert.event, record.process_id());
                            info!(
                                target: TARGET_ENGINE,
                                rule = %alert.rule_name,
                                severity = ?alert.severity,
                                category = ?alert.event.category,
                                "IOC detection triggered"
                            );
                            self.alert_sink.write_alert(&alert);
                            self.response_engine.handle_alert(&alert);
                        }
                    }
                }
            }
            None => {
                if category == EventCategory::Process && record.opcode() == 2 {
                    tracing::trace!(
                        target: TARGET_ENGINE,
                        "Process stop event processed for cache maintenance"
                    );
                    return;
                }

                // Failed normalization - only log in debug mode
                debug!(
                    target: TARGET_ENGINE,
                    category = ?category,
                    event_id = record.event_id(),
                    opcode = record.opcode(),
                    "Failed to normalize event"
                );
            }
        }
    }
}
