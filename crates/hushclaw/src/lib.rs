//! Hushclaw - Security policy enforcement guards for AI agent runtimes
//!
//! This crate provides modular security guards that check execution events
//! against configured security policies.

pub mod error;
pub mod event;
pub mod guards;
pub mod policy;

pub use error::{Error, Result, Severity};
pub use event::{Event, EventData, EventType};
pub use guards::{Guard, GuardRegistry, GuardResult};
pub use policy::Policy;
