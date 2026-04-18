//! Protobuf-generated types for alert delivery.
//!
//! These types are generated at build time from proto/alert.proto.
//! Do not edit the generated files directly.

// Include the generated protobuf code.
include!(concat!(env!("OUT_DIR"), "/aegis.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_creation() {
        let alert = Alert {
            alert_id: "test-001".to_string(),
            rule_name: "suspicious_memory_access".to_string(),
            severity: Severity::High as i32,
            message: "Detected suspicious memory access pattern".to_string(),
            tgid: 1234,
            process_name: "malware".to_string(),
            timestamp_ns: 1_234_567_890_000,
            context_json: "{}".to_string(),
        };

        assert_eq!(alert.alert_id, "test-001");
        assert_eq!(alert.severity, Severity::High as i32);
    }

    #[test]
    fn test_alert_batch() {
        let alert1 = Alert {
            alert_id: "a1".to_string(),
            rule_name: "rule1".to_string(),
            severity: Severity::Medium as i32,
            message: "msg1".to_string(),
            tgid: 100,
            process_name: "proc1".to_string(),
            timestamp_ns: 1000,
            context_json: "{}".to_string(),
        };

        let alert2 = Alert {
            alert_id: "a2".to_string(),
            rule_name: "rule2".to_string(),
            severity: Severity::Critical as i32,
            message: "msg2".to_string(),
            tgid: 200,
            process_name: "proc2".to_string(),
            timestamp_ns: 2000,
            context_json: "{}".to_string(),
        };

        let batch = AlertBatch {
            alerts: vec![alert1, alert2],
        };

        assert_eq!(batch.alerts.len(), 2);
        assert_eq!(batch.alerts[0].alert_id, "a1");
        assert_eq!(batch.alerts[1].severity, Severity::Critical as i32);
    }

    #[test]
    fn test_severity_enum() {
        assert_eq!(Severity::Unspecified as i32, 0);
        assert_eq!(Severity::Info as i32, 1);
        assert_eq!(Severity::Low as i32, 2);
        assert_eq!(Severity::Medium as i32, 3);
        assert_eq!(Severity::High as i32, 4);
        assert_eq!(Severity::Critical as i32, 5);
    }
}
