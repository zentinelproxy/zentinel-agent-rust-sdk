//! Testing utilities for agent development.
//!
//! Enable the `testing` crate feature to use these helpers in integration tests.

use crate::agent::AgentHandler;
pub use crate::agent::{REQUEST_CACHE_MAX_AGE, REQUEST_CACHE_MAX_ENTRIES};
use crate::Agent;
use std::collections::HashMap;
use zentinel_agent_protocol::RequestHeadersEvent;
use zentinel_agent_protocol::RequestMetadata;

/// Returns the current correlation cache entry count for an [`AgentHandler`].
pub async fn request_cache_len<A: Agent>(handler: &AgentHandler<A>) -> usize {
    handler.correlation_cache_len().await
}

/// Build a minimal [`RequestHeadersEvent`] for tests.
pub fn request_headers_event(correlation_id: &str, uri: &str) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: correlation_id.to_string(),
            request_id: format!("req-{correlation_id}"),
            client_ip: "127.0.0.1".to_string(),
            client_port: 80,
            server_name: None,
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            traceparent: None,
        },
        method: "GET".to_string(),
        uri: uri.to_string(),
        headers: HashMap::new(),
    }
}
