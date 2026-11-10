//! Simplified agent trait and handler definitions.
//!
//! This module provides a more ergonomic interface for building agents
//! compared to the low-level protocol handler.

#![allow(clippy::double_must_use)] // triggered by `async_trait` on Rust 1.99+

use crate::{Decision, Request, Response};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;
use zentinel_agent_protocol::v2::{AgentCapabilities, AgentHandlerV2};
use zentinel_agent_protocol::{AgentResponse, EventType};

/// Maximum number of in-flight request correlation entries retained by [`AgentHandler`].
pub const REQUEST_CACHE_MAX_ENTRIES: usize = 100_000;

/// Maximum age of a correlation cache entry before it becomes eligible for sweep eviction.
pub const REQUEST_CACHE_MAX_AGE: Duration = Duration::from_secs(120);

/// Upper bound on expired entries removed per cache insert (amortized sweep work).
const REQUEST_CACHE_SWEEP_BUDGET: usize = 64;

/// Correlation context for a single in-flight request.
#[derive(Debug, Clone)]
struct CachedRequest {
    request: Request,
    inserted_at: Instant,
}

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
    ///
    /// # Correlation cache
    ///
    /// If the proxy delivers a body chunk after the SDK has released the matching
    /// correlation entry (response headers processed, TTL sweep, or cache at capacity),
    /// the SDK **does not** call this method and instead returns a block decision to
    /// the proxy (fail-closed). See [`AgentHandler`] for details.
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
///
/// # Correlation cache
///
/// When the declared [`AgentCapabilities`] include body/response/complete events,
/// the handler caches each request keyed by correlation ID until:
///
/// - response headers are processed (request body inspection is finished), unless
///   the agent also declared [`EventType::ResponseBodyChunk`];
/// - the final response body chunk (`is_last`) is processed, when response body
///   inspection is declared;
/// - [`AgentHandlerV2::on_request_complete`] runs; or
/// - the entry exceeds [`REQUEST_CACHE_MAX_AGE`] and is removed by a bounded sweep, or
///   the map is already at [`REQUEST_CACHE_MAX_ENTRIES`] and a new insert is refused.
///
/// If the map is full, new inserts are **not** accepted (no LRU eviction) so a parked
/// POST cannot displace another request's correlation state. The handler returns a
/// block decision for that request headers event.
///
/// ## Missing correlation (fail-closed)
///
/// `on_request_body_chunk`, `on_response_headers`, and `on_response_body_chunk`
/// require a cache hit. On a miss the handler returns **403 Forbidden** with body
/// `"Request correlation context unavailable (expired or evicted)"` and does not
/// invoke the [`Agent`] hook. This is a behaviour change from earlier releases
/// that silently allowed traffic on cache miss.
pub struct AgentHandler<A: Agent> {
    agent: Arc<A>,
    request_cache: RwLock<HashMap<String, CachedRequest>>,
    capabilities: AgentCapabilities,
}

impl<A: Agent> AgentHandler<A> {
    /// Create a new handler wrapping the given agent.
    ///
    /// Default capabilities declare only [`EventType::RequestHeaders`], so no
    /// correlation cache is used unless you call [`Self::with_capabilities`].
    pub fn new(agent: A) -> Self {
        let name = agent.name().to_string();
        Self {
            agent: Arc::new(agent),
            request_cache: RwLock::new(HashMap::new()),
            capabilities: AgentCapabilities::new(&name, &name, env!("CARGO_PKG_VERSION"))
                .with_event(EventType::RequestHeaders),
        }
    }

    /// Override negotiated capabilities (and therefore when correlation state is cached).
    pub fn with_capabilities(mut self, capabilities: AgentCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Get a reference to the underlying agent.
    pub fn agent(&self) -> &A {
        &self.agent
    }

    /// Number of in-flight correlation cache entries (for tests and diagnostics).
    #[cfg(feature = "testing")]
    pub async fn correlation_cache_len(&self) -> usize {
        self.request_cache.read().await.len()
    }

    fn correlation_cache_required(&self) -> bool {
        [
            EventType::RequestBodyChunk,
            EventType::ResponseHeaders,
            EventType::ResponseBodyChunk,
            EventType::RequestComplete,
        ]
        .into_iter()
        .any(|event| self.capabilities.supports_event(event))
    }

    fn sweep_expired(&self, cache: &mut HashMap<String, CachedRequest>) {
        let now = Instant::now();
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.inserted_at) >= REQUEST_CACHE_MAX_AGE)
            .map(|(key, _)| key.clone())
            .take(REQUEST_CACHE_SWEEP_BUDGET)
            .collect();
        for key in expired_keys {
            cache.remove(&key);
        }
    }

    async fn try_insert_cache(
        &self,
        correlation_id: String,
        request: Request,
    ) -> Option<AgentResponse> {
        let mut cache = self.request_cache.write().await;
        self.sweep_expired(&mut cache);
        if cache.len() >= REQUEST_CACHE_MAX_ENTRIES && !cache.contains_key(&correlation_id) {
            return Some(cache_capacity_response());
        }
        cache.insert(
            correlation_id,
            CachedRequest {
                request,
                inserted_at: Instant::now(),
            },
        );
        None
    }

    async fn remove_cached(&self, correlation_id: &str) {
        self.request_cache.write().await.remove(correlation_id);
    }
}

fn missing_correlation_response() -> AgentResponse {
    Decision::deny()
        .with_body("Request correlation context unavailable (expired or evicted)")
        .with_tag("correlation-cache-miss")
        .build()
}

fn cache_capacity_response() -> AgentResponse {
    Decision::block(503)
        .with_body("Agent correlation cache at capacity")
        .with_tag("correlation-cache-full")
        .build()
}

#[async_trait]
impl<A: Agent> AgentHandlerV2 for AgentHandler<A> {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn on_configure(&self, config: serde_json::Value, _version: Option<String>) -> bool {
        self.agent.on_configure(config).await.is_ok()
    }

    async fn on_request_headers(
        &self,
        event: zentinel_agent_protocol::RequestHeadersEvent,
    ) -> AgentResponse {
        let request = Request::from_headers_event(&event);

        let correlation_id = request.correlation_id().to_string();
        if self.correlation_cache_required() {
            if let Some(response) = self
                .try_insert_cache(correlation_id.clone(), request.clone())
                .await
            {
                return response;
            }
        }

        let decision = self.agent.on_request(&request).await;
        let wants_more = decision.clone().build().needs_more;
        let response = decision.build();

        if self.correlation_cache_required()
            && !wants_more
            && !self
                .capabilities
                .supports_event(EventType::RequestBodyChunk)
            && !self.capabilities.supports_event(EventType::ResponseHeaders)
            && !self
                .capabilities
                .supports_event(EventType::ResponseBodyChunk)
        {
            // Only RequestComplete (or similar) remains; keep until complete or sweep.
            if !self.capabilities.supports_event(EventType::RequestComplete) {
                self.remove_cached(&correlation_id).await;
            }
        }

        response
    }

    async fn on_request_body_chunk(
        &self,
        event: zentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        let cache = self.request_cache.read().await;
        let Some(cached) = cache.get(&event.correlation_id) else {
            return missing_correlation_response();
        };
        let body = base64_decode(&event.data).unwrap_or_default();
        let request_with_body = cached.request.clone().with_body(body);
        drop(cache);
        self.agent.on_request_body(&request_with_body).await.build()
    }

    async fn on_response_headers(
        &self,
        event: zentinel_agent_protocol::ResponseHeadersEvent,
    ) -> AgentResponse {
        let response = Response::from_headers_event(&event);
        let correlation_id = event.correlation_id.clone();

        let cache = self.request_cache.read().await;
        let Some(cached) = cache.get(&correlation_id) else {
            return missing_correlation_response();
        };
        let request = cached.request.clone();
        drop(cache);

        let agent_response = self.agent.on_response(&request, &response).await.build();

        if !self
            .capabilities
            .supports_event(EventType::ResponseBodyChunk)
        {
            self.remove_cached(&correlation_id).await;
        }

        agent_response
    }

    async fn on_response_body_chunk(
        &self,
        event: zentinel_agent_protocol::ResponseBodyChunkEvent,
    ) -> AgentResponse {
        let cache = self.request_cache.read().await;
        let Some(cached) = cache.get(&event.correlation_id) else {
            return missing_correlation_response();
        };
        let body = base64_decode(&event.data).unwrap_or_default();
        let response =
            Response::from_headers_event(&zentinel_agent_protocol::ResponseHeadersEvent {
                correlation_id: event.correlation_id.clone(),
                status: 200,
                headers: HashMap::new(),
            })
            .with_body(body);
        let request = cached.request.clone();
        drop(cache);

        let agent_response = self
            .agent
            .on_response_body(&request, &response)
            .await
            .build();

        if event.is_last {
            self.remove_cached(&event.correlation_id).await;
        }

        agent_response
    }

    async fn on_request_complete(
        &self,
        event: zentinel_agent_protocol::RequestCompleteEvent,
    ) -> AgentResponse {
        let request = self
            .request_cache
            .write()
            .await
            .remove(&event.correlation_id)
            .map(|cached| cached.request);

        if let Some(request) = request {
            self.agent
                .on_request_complete(&request, event.status, event.duration_ms)
                .await;
        }

        AgentResponse::default_allow()
    }
}

/// Decode base64 string to bytes
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let bytes = s.as_bytes();
    let mut decoder =
        base64::read::DecoderReader::new(bytes, &base64::engine::general_purpose::STANDARD);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

#[cfg(test)]
impl<A: Agent> AgentHandler<A> {
    async fn cache_len(&self) -> usize {
        self.request_cache.read().await.len()
    }

    fn test_capabilities_all_events(agent_name: &str) -> AgentCapabilities {
        AgentCapabilities::new(agent_name, agent_name, env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_event(EventType::ResponseHeaders)
            .with_event(EventType::ResponseBodyChunk)
            .with_event(EventType::RequestComplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
    use zentinel_agent_protocol::Decision as ProtocolDecision;

    fn sample_request_event(correlation_id: &str) -> zentinel_agent_protocol::RequestHeadersEvent {
        zentinel_agent_protocol::RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: correlation_id.to_string(),
                request_id: format!("req-{correlation_id}"),
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
        }
    }

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
        use zentinel_agent_protocol::v2::AgentHandlerV2 as ProtocolHandler;

        let agent = MetricsAgent::new();
        let handler = AgentHandler::new(agent).with_capabilities(
            AgentHandler::<MetricsAgent>::test_capabilities_all_events("metrics-agent"),
        );

        handler
            .on_request_headers(sample_request_event("test-123"))
            .await;

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

        assert_eq!(handler.agent().completed_status.load(Ordering::SeqCst), 200);
        assert_eq!(
            handler.agent().completed_duration.load(Ordering::SeqCst),
            42
        );
        assert_eq!(handler.cache_len().await, 0);
    }

    #[tokio::test]
    async fn test_request_cache_empty_for_headers_only_capabilities() {
        use zentinel_agent_protocol::v2::AgentHandlerV2 as ProtocolHandler;

        let handler = AgentHandler::new(TestAgent);
        for i in 0..10_000 {
            handler
                .on_request_headers(sample_request_event(&format!("cid-{i}")))
                .await;
        }
        assert_eq!(handler.cache_len().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_request_cache_sweep_bounds_stale_entries() {
        use zentinel_agent_protocol::v2::AgentHandlerV2 as ProtocolHandler;

        let handler = AgentHandler::new(TestAgent).with_capabilities(
            AgentHandler::<TestAgent>::test_capabilities_all_events("test-agent"),
        );

        for i in 0..50 {
            handler
                .on_request_headers(sample_request_event(&format!("stale-{i}")))
                .await;
        }
        assert_eq!(handler.cache_len().await, 50);

        tokio::time::advance(REQUEST_CACHE_MAX_AGE + Duration::from_secs(1)).await;
        handler
            .on_request_headers(sample_request_event("stale-fresh"))
            .await;

        assert!(handler.cache_len().await < 50);
    }

    #[tokio::test]
    async fn test_body_chunk_after_eviction_fails_closed() {
        use zentinel_agent_protocol::v2::AgentHandlerV2 as ProtocolHandler;

        let handler = AgentHandler::new(TestAgent).with_capabilities(
            AgentHandler::<TestAgent>::test_capabilities_all_events("test-agent"),
        );

        handler
            .on_request_headers(sample_request_event("evict-me"))
            .await;

        handler.remove_cached("evict-me").await;

        let body_event = zentinel_agent_protocol::RequestBodyChunkEvent {
            correlation_id: "evict-me".to_string(),
            data: String::new(),
            is_last: true,
            total_size: None,
            chunk_index: 0,
            bytes_received: 0,
        };
        let response = handler.on_request_body_chunk(body_event).await;

        assert!(matches!(
            response.decision,
            ProtocolDecision::Block { status: 403, .. }
        ));
    }
}
