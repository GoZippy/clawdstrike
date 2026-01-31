//! Execution events that guards evaluate

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Execution event to be checked by guards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    pub event_id: String,
    /// Event type
    pub event_type: EventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Associated run ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Event-specific data
    pub data: EventData,
}

impl Event {
    /// Create a file read event
    pub fn file_read(path: impl Into<String>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::FileRead,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::File(FileEventData {
                path: path.into(),
                content_hash: None,
            }),
        }
    }

    /// Create a file write event
    pub fn file_write(path: impl Into<String>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::FileWrite,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::File(FileEventData {
                path: path.into(),
                content_hash: None,
            }),
        }
    }

    /// Create a network egress event
    pub fn network_egress(host: impl Into<String>, port: u16) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::NetworkEgress,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::Network(NetworkEventData {
                host: host.into(),
                port,
                protocol: None,
            }),
        }
    }

    /// Create a command execution event
    pub fn command_exec(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::CommandExec,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::Command(CommandEventData {
                command: command.into(),
                args,
                working_dir: None,
            }),
        }
    }

    /// Create a tool call event
    pub fn tool_call(tool_name: impl Into<String>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::ToolCall,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::Tool(ToolEventData {
                tool_name: tool_name.into(),
                parameters: HashMap::new(),
            }),
        }
    }

    /// Create a patch application event
    pub fn patch_apply(file_path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::PatchApply,
            timestamp: Utc::now(),
            run_id: None,
            data: EventData::Patch(PatchEventData {
                file_path: file_path.into(),
                patch_content: content.into(),
                patch_hash: None,
            }),
        }
    }

    /// Set the run ID
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }
}

/// Type of execution event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FileRead,
    FileWrite,
    CommandExec,
    NetworkEgress,
    ToolCall,
    PatchApply,
}

/// Event-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    File(FileEventData),
    Command(CommandEventData),
    Network(NetworkEventData),
    Tool(ToolEventData),
    Patch(PatchEventData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventData {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEventData {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventData {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEventData {
    pub tool_name: String,
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchEventData {
    pub file_path: String,
    pub patch_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_read_event() {
        let event = Event::file_read("/etc/passwd");
        assert_eq!(event.event_type, EventType::FileRead);
        match event.data {
            EventData::File(f) => assert_eq!(f.path, "/etc/passwd"),
            _ => panic!("Expected File event data"),
        }
    }

    #[test]
    fn test_network_event() {
        let event = Event::network_egress("api.github.com", 443);
        assert_eq!(event.event_type, EventType::NetworkEgress);
        match event.data {
            EventData::Network(n) => {
                assert_eq!(n.host, "api.github.com");
                assert_eq!(n.port, 443);
            }
            _ => panic!("Expected Network event data"),
        }
    }

    #[test]
    fn test_patch_event() {
        let event = Event::patch_apply("/tmp/file.py", "print('hello')");
        assert_eq!(event.event_type, EventType::PatchApply);
        match event.data {
            EventData::Patch(p) => {
                assert_eq!(p.file_path, "/tmp/file.py");
                assert_eq!(p.patch_content, "print('hello')");
            }
            _ => panic!("Expected Patch event data"),
        }
    }

    #[test]
    fn test_event_with_run_id() {
        let event = Event::file_read("/tmp/test").with_run_id("run-123");
        assert_eq!(event.run_id, Some("run-123".to_string()));
    }
}
