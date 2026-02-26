//! Simplified agent trait and handler definitions.
//!
//! This module provides a more ergonomic interface for building agents
//! compared to the low-level protocol handler.

use crate::{Decision, Request, Response};
use async_trait::async_trait;
use zentinel_agent_protocol::{
    AgentResponse, Decision as ProtocolDecision, GuardrailInspectEvent, GuardrailResponse,
};
use zentinel_agent_protocol::v2::PROTOCOL_VERSION_2;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A simplified agent trait for processing HTTP traffic.
///
/// Implement this trait to create a Zentinel agent. The SDK handles
/// protocol details, connection management, and error handling.
///
/// # Example
///
/// ```ignore
/// use zentinel_agent_sdk::{Agent, Request, Decision};
/// use async_trait::async_trait;
///
/// struct MyAgent;
///
/// #[async_trait]
/// impl Agent for MyAgent {
///     async fn on_request(&self, request: &Request) -> Decision {
///         if request.path_starts_with("/admin") {
///             Decision::deny()
///         } else {
///             Decision::allow()
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Agent: Send + Sync + 'static {
    /// Agent name for logging and identification.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// Called when the agent receives configuration from the proxy.
    ///
    /// Return `Ok(())` to accept the configuration, or `Err(message)`
    /// to reject it (which will prevent the proxy from starting).
    ///
    /// The default implementation accepts any configuration.
    async fn on_configure(&self, _config: serde_json::Value) -> Result<(), String> {
        Ok(())
    }

    /// Called for each incoming request (after headers received).
    ///
    /// This is the main entry point for request processing.
    /// Return a decision to allow, block, or modify the request.
    async fn on_request(&self, request: &Request) -> Decision {
        let _ = request;
        Decision::allow()
    }

    /// Called when the request body is available.
    ///
    /// Only called if body inspection is enabled for this agent.
    /// The request includes the accumulated body.
    async fn on_request_body(&self, request: &Request) -> Decision {
        let _ = request;
        Decision::allow()
    }

    /// Called when response headers are received from upstream.
    ///
    /// Allows modifying response headers before sending to client.
    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        let _ = (request, response);
        Decision::allow()
    }

    /// Called when the response body is available.
    ///
    /// Only called if response body inspection is enabled.
    async fn on_response_body(&self, request: &Request, response: &Response) -> Decision {
        let _ = (request, response);
        Decision::allow()
    }

    /// Called when request processing is complete.
    ///
    /// Use this for logging, metrics collection, or cleanup.
    /// This is called after the response has been sent to the client.
    ///
    /// # Arguments
    /// * `request` - The original request
    /// * `status` - The final HTTP status code sent to the client
    /// * `duration_ms` - Total request processing time in milliseconds
    async fn on_request_complete(&self, request: &Request, status: u16, duration_ms: u64) {
        let _ = (request, status, duration_ms);
    }

    /// Inspect content for guardrail violations.
    ///
    /// Called when content needs to be analyzed for prompt injection
    /// or PII detection. Override to implement custom guardrail logic.
    ///
    /// # Arguments
    /// * `event` - The guardrail inspection event containing content and parameters
    async fn on_guardrail_inspect(&self, event: &GuardrailInspectEvent) -> GuardrailResponse {
        let _ = event;
        GuardrailResponse::clean()
    }
}

/// A configurable agent that deserializes its configuration.
///
/// This trait extends `Agent` with typed configuration handling.
///
/// # Example
///
/// ```ignore
/// use zentinel_agent_sdk::{ConfigurableAgent, Request, Decision};
/// use serde::Deserialize;
///
/// #[derive(Default, Deserialize)]
/// #[serde(rename_all = "kebab-case")]
/// struct MyConfig {
///     enabled: bool,
///     threshold: u32,
/// }
///
/// struct MyAgent {
///     config: tokio::sync::RwLock<MyConfig>,
/// }
///
/// impl ConfigurableAgent for MyAgent {
///     type Config = MyConfig;
///
///     fn config(&self) -> &tokio::sync::RwLock<Self::Config> {
///         &self.config
///     }
/// }
/// ```
pub trait ConfigurableAgent: Agent {
    /// The configuration type for this agent.
    type Config: DeserializeOwned + Send + Sync + Default;

    /// Get a reference to the configuration storage.
    fn config(&self) -> &RwLock<Self::Config>;

    /// Called after configuration is successfully applied.
    ///
    /// Override this to perform additional setup after config changes.
    fn on_config_applied(&self, _config: &Self::Config) {}
}

/// Extension trait providing default `on_configure` for configurable agents.
#[async_trait]
pub trait ConfigurableAgentExt: ConfigurableAgent {
    /// Parse and apply configuration.
    async fn apply_config(&self, config_json: serde_json::Value) -> Result<(), String> {
        let config: Self::Config = serde_json::from_value(config_json)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        self.on_config_applied(&config);
        *self.config().write().await = config;
        Ok(())
    }
}

impl<T: ConfigurableAgent> ConfigurableAgentExt for T {}

/// Handler adapter that bridges the simplified Agent trait to the protocol.
///
/// This type holds a reference to your agent and stores request context
/// for correlation between request and response events.
pub struct AgentHandler<A: Agent> {
    agent: Arc<A>,
    /// Cache of request headers by correlation ID for response events
    request_cache: RwLock<HashMap<String, Request>>,
}

impl<A: Agent> AgentHandler<A> {
    /// Create a new handler wrapping the given agent.
    pub fn new(agent: A) -> Self {
        Self {
            agent: Arc::new(agent),
            request_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get a reference to the underlying agent.
    pub fn agent(&self) -> &A {
        &self.agent
    }
}

#[async_trait]
impl<A: Agent> zentinel_agent_protocol::AgentHandler for AgentHandler<A> {
    async fn on_configure(
        &self,
        event: zentinel_agent_protocol::ConfigureEvent,
    ) -> AgentResponse {
        match self.agent.on_configure(event.config).await {
            Ok(()) => AgentResponse::default_allow(),
            Err(msg) => AgentResponse {
                version: PROTOCOL_VERSION_2,
                decision: ProtocolDecision::Block {
                    status: 500,
                    body: Some(msg),
                    headers: None,
                },
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: HashMap::new(),
                audit: Default::default(),
                needs_more: false,
                request_body_mutation: None,
                response_body_mutation: None,
                websocket_decision: None,
            },
        }
    }

    async fn on_request_headers(
        &self,
        event: zentinel_agent_protocol::RequestHeadersEvent,
    ) -> AgentResponse {
        let request = Request::from_headers_event(&event);

        // Cache the request for later response processing
        let correlation_id = request.correlation_id().to_string();
        self.request_cache.write().await.insert(correlation_id, request.clone());

        self.agent.on_request(&request).await.build()
    }

    async fn on_request_body_chunk(
        &self,
        event: zentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        // Get cached request and add body
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            // Decode base64 body
            let body = base64_decode(&event.data).unwrap_or_default();
            let request_with_body = request.clone().with_body(body);
            drop(cache);
            return self.agent.on_request_body(&request_with_body).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_response_headers(
        &self,
        event: zentinel_agent_protocol::ResponseHeadersEvent,
    ) -> AgentResponse {
        let response = Response::from_headers_event(&event);

        // Get cached request
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            return self.agent.on_response(request, &response).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(
        &self,
        event: zentinel_agent_protocol::ResponseBodyChunkEvent,
    ) -> AgentResponse {
        // For response body, we need both request and response context
        // This is a simplified implementation - full implementation would
        // also cache response headers
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            // Create a minimal response with body
            let body = base64_decode(&event.data).unwrap_or_default();
            let response = Response::from_headers_event(&zentinel_agent_protocol::ResponseHeadersEvent {
                correlation_id: event.correlation_id.clone(),
                status: 200,
                headers: HashMap::new(),
            }).with_body(body);
            return self.agent.on_response_body(request, &response).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_request_complete(
        &self,
        event: zentinel_agent_protocol::RequestCompleteEvent,
    ) -> AgentResponse {
        // Get cached request for the callback
        let request = self.request_cache.write().await.remove(&event.correlation_id);

        // Call the agent's on_request_complete hook if we have request context
        if let Some(request) = request {
            self.agent.on_request_complete(
                &request,
                event.status,
                event.duration_ms,
            ).await;
        }

        AgentResponse::default_allow()
    }

    async fn on_guardrail_inspect(
        &self,
        event: GuardrailInspectEvent,
    ) -> AgentResponse {
        let response = self.agent.on_guardrail_inspect(&event).await;

        // Build response with guardrail_response in audit.custom
        let tags = if response.detected {
            vec!["guardrail_detected".to_string()]
        } else {
            vec![]
        };

        let rule_ids: Vec<String> = response
            .detections
            .iter()
            .map(|d| d.category.clone())
            .collect();

        AgentResponse {
            version: PROTOCOL_VERSION_2,
            decision: ProtocolDecision::Allow,
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: zentinel_agent_protocol::AuditMetadata {
                tags,
                rule_ids,
                confidence: Some(response.confidence as f32),
                reason_codes: vec![],
                custom: {
                    let mut custom = HashMap::new();
                    custom.insert(
                        "guardrail_response".to_string(),
                        serde_json::to_value(&response).unwrap_or_default(),
                    );
                    custom
                },
            },
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }
}

/// Decode base64 string to bytes
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let bytes = s.as_bytes();
    let mut decoder = base64::read::DecoderReader::new(bytes, &base64::engine::general_purpose::STANDARD);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

    struct TestAgent;

    #[async_trait]
    impl Agent for TestAgent {
        fn name(&self) -> &str {
            "test-agent"
        }

        async fn on_request(&self, request: &Request) -> Decision {
            if request.path_starts_with("/blocked") {
                Decision::deny().with_body("Blocked")
            } else {
                Decision::allow()
            }
        }
    }

    #[tokio::test]
    async fn test_agent_handler() {
        let handler = AgentHandler::new(TestAgent);
        assert_eq!(handler.agent().name(), "test-agent");
    }

    struct MetricsAgent {
        completed_status: AtomicU16,
        completed_duration: AtomicU64,
    }

    impl MetricsAgent {
        fn new() -> Self {
            Self {
                completed_status: AtomicU16::new(0),
                completed_duration: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl Agent for MetricsAgent {
        fn name(&self) -> &str {
            "metrics-agent"
        }

        async fn on_request_complete(&self, _request: &Request, status: u16, duration_ms: u64) {
            self.completed_status.store(status, Ordering::SeqCst);
            self.completed_duration.store(duration_ms, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_on_request_complete() {
        use zentinel_agent_protocol::AgentHandler as ProtocolHandler;

        let agent = MetricsAgent::new();
        let handler = AgentHandler::new(agent);

        // First send a request to populate the cache
        let request_event = zentinel_agent_protocol::RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
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
            uri: "/test".to_string(),
            headers: HashMap::new(),
        };
        handler.on_request_headers(request_event).await;

        // Now send the complete event
        let complete_event = zentinel_agent_protocol::RequestCompleteEvent {
            correlation_id: "test-123".to_string(),
            status: 200,
            duration_ms: 42,
            request_body_size: 0,
            response_body_size: 0,
            upstream_attempts: 1,
            error: None,
        };
        handler.on_request_complete(complete_event).await;

        // Verify the callback was invoked
        assert_eq!(handler.agent().completed_status.load(Ordering::SeqCst), 200);
        assert_eq!(handler.agent().completed_duration.load(Ordering::SeqCst), 42);
    }
}
