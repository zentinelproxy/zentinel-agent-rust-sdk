//! Decision builder with fluent API.
//!
//! Provides an ergonomic way to construct agent responses.

use zentinel_agent_protocol::{AgentResponse, AuditMetadata, BodyMutation, Decision as ProtocolDecision, HeaderOp};
use zentinel_agent_protocol::v2::PROTOCOL_VERSION_2;
use std::collections::HashMap;

/// A builder for constructing agent decisions.
///
/// # Examples
///
/// ```ignore
/// use zentinel_agent_sdk::Decision;
///
/// // Simple allow
/// let decision = Decision::allow();
///
/// // Block with status
/// let decision = Decision::block(403)
///     .with_body("Access denied");
///
/// // Allow with header modifications
/// let decision = Decision::allow()
///     .add_request_header("X-User-ID", "12345")
///     .add_response_header("X-Processed-By", "my-agent")
///     .with_tag("authenticated");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Decision {
    decision: DecisionType,
    status_code: Option<u16>,
    body: Option<String>,
    block_headers: Option<HashMap<String, String>>,
    add_request_headers: HashMap<String, String>,
    remove_request_headers: Vec<String>,
    add_response_headers: HashMap<String, String>,
    remove_response_headers: Vec<String>,
    tags: Vec<String>,
    custom_metadata: HashMap<String, serde_json::Value>,
    rule_ids: Vec<String>,
    confidence: Option<f32>,
    reason_codes: Vec<String>,
    routing_metadata: HashMap<String, String>,
    needs_more: bool,
    request_body_mutation: Option<BodyMutation>,
    response_body_mutation: Option<BodyMutation>,
}

#[derive(Debug, Clone, Default)]
enum DecisionType {
    #[default]
    Allow,
    Block,
    Redirect(String),
    Challenge {
        challenge_type: String,
        params: HashMap<String, String>,
    },
}

impl Decision {
    /// Create an allow decision.
    ///
    /// The request will continue to the upstream.
    pub fn allow() -> Self {
        Self {
            decision: DecisionType::Allow,
            ..Default::default()
        }
    }

    /// Create a block decision with a status code.
    ///
    /// The request will be rejected with the given status code.
    pub fn block(status_code: u16) -> Self {
        Self {
            decision: DecisionType::Block,
            status_code: Some(status_code),
            ..Default::default()
        }
    }

    /// Create a deny decision (403 Forbidden).
    ///
    /// Convenience method for `Decision::block(403)`.
    pub fn deny() -> Self {
        Self::block(403)
    }

    /// Create an unauthorized decision (401 Unauthorized).
    ///
    /// Convenience method for `Decision::block(401)`.
    pub fn unauthorized() -> Self {
        Self::block(401)
    }

    /// Create a rate limited decision (429 Too Many Requests).
    ///
    /// Convenience method for `Decision::block(429)`.
    pub fn rate_limited() -> Self {
        Self::block(429)
    }

    /// Create a redirect decision.
    ///
    /// The request will be redirected to the given URL with 302 status.
    pub fn redirect(url: impl Into<String>) -> Self {
        Self {
            decision: DecisionType::Redirect(url.into()),
            status_code: Some(302),
            ..Default::default()
        }
    }

    /// Create a permanent redirect (301).
    pub fn redirect_permanent(url: impl Into<String>) -> Self {
        Self {
            decision: DecisionType::Redirect(url.into()),
            status_code: Some(301),
            ..Default::default()
        }
    }

    /// Create a challenge decision (e.g., CAPTCHA, JavaScript challenge).
    ///
    /// The client will be presented with a challenge before proceeding.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zentinel_agent_sdk::Decision;
    /// use std::collections::HashMap;
    ///
    /// // Simple challenge
    /// let decision = Decision::challenge("captcha", HashMap::new());
    ///
    /// // Challenge with parameters
    /// let mut params = HashMap::new();
    /// params.insert("site_key".to_string(), "abc123".to_string());
    /// let decision = Decision::challenge("captcha", params);
    /// ```
    pub fn challenge(
        challenge_type: impl Into<String>,
        params: HashMap<String, String>,
    ) -> Self {
        Self {
            decision: DecisionType::Challenge {
                challenge_type: challenge_type.into(),
                params,
            },
            ..Default::default()
        }
    }

    /// Set the response body for block/error responses.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the response body as JSON.
    pub fn with_json_body<T: serde::Serialize>(mut self, value: &T) -> Self {
        if let Ok(json) = serde_json::to_string(value) {
            self.body = Some(json);
        }
        self
    }

    /// Add a header to the block response.
    pub fn with_block_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.block_headers
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value.into());
        self
    }

    /// Add a header to the request (sent to upstream).
    pub fn add_request_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_request_headers.insert(name.into(), value.into());
        self
    }

    /// Remove a header from the request.
    pub fn remove_request_header(mut self, name: impl Into<String>) -> Self {
        self.remove_request_headers.push(name.into());
        self
    }

    /// Add a header to the response (sent to client).
    pub fn add_response_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_response_headers.insert(name.into(), value.into());
        self
    }

    /// Remove a header from the response.
    pub fn remove_response_header(mut self, name: impl Into<String>) -> Self {
        self.remove_response_headers.push(name.into());
        self
    }

    /// Add an audit tag for logging/tracing.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple audit tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(|t| t.into()));
        self
    }

    /// Add custom metadata for logging/tracing.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.custom_metadata.insert(key.into(), value.into());
        self
    }

    /// Add a rule ID for audit/compliance tracking.
    ///
    /// Rule IDs identify which security rules triggered the decision.
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_ids.push(rule_id.into());
        self
    }

    /// Add multiple rule IDs.
    pub fn with_rule_ids(mut self, rule_ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.rule_ids.extend(rule_ids.into_iter().map(|r| r.into()));
        self
    }

    /// Set the confidence score for the decision (0.0 to 1.0).
    ///
    /// Useful for ML-based decisions or probabilistic matching.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence.clamp(0.0, 1.0));
        self
    }

    /// Add a reason code explaining the decision.
    ///
    /// Reason codes provide structured explanations for audit trails.
    pub fn with_reason_code(mut self, code: impl Into<String>) -> Self {
        self.reason_codes.push(code.into());
        self
    }

    /// Add multiple reason codes.
    pub fn with_reason_codes(mut self, codes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.reason_codes.extend(codes.into_iter().map(|c| c.into()));
        self
    }

    /// Add routing metadata for upstream selection/load balancing.
    ///
    /// This metadata can influence how the proxy routes the request.
    pub fn with_routing_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.routing_metadata.insert(key.into(), value.into());
        self
    }

    /// Indicate that more data is needed before making a final decision.
    ///
    /// Use this when body inspection is required but not yet available.
    pub fn needs_more_data(mut self) -> Self {
        self.needs_more = true;
        self
    }

    /// Set a mutation to apply to the request body.
    ///
    /// Use `BodyMutation::replace(chunk_index, data)` to replace a chunk,
    /// `BodyMutation::drop_chunk(chunk_index)` to drop it, or
    /// `BodyMutation::pass_through(chunk_index)` to leave it unchanged.
    pub fn with_request_body_mutation(mut self, mutation: BodyMutation) -> Self {
        self.request_body_mutation = Some(mutation);
        self
    }

    /// Set a mutation to apply to the response body.
    ///
    /// Use `BodyMutation::replace(chunk_index, data)` to replace a chunk,
    /// `BodyMutation::drop_chunk(chunk_index)` to drop it, or
    /// `BodyMutation::pass_through(chunk_index)` to leave it unchanged.
    pub fn with_response_body_mutation(mut self, mutation: BodyMutation) -> Self {
        self.response_body_mutation = Some(mutation);
        self
    }

    /// Build the protocol response.
    pub fn build(self) -> AgentResponse {
        let decision = match &self.decision {
            DecisionType::Allow => ProtocolDecision::Allow,
            DecisionType::Block => ProtocolDecision::Block {
                status: self.status_code.unwrap_or(403),
                body: self.body.clone(),
                headers: self.block_headers.clone(),
            },
            DecisionType::Redirect(url) => ProtocolDecision::Redirect {
                url: url.clone(),
                status: self.status_code.unwrap_or(302),
            },
            DecisionType::Challenge { challenge_type, params } => ProtocolDecision::Challenge {
                challenge_type: challenge_type.clone(),
                params: params.clone(),
            },
        };

        let request_headers = self.build_request_mutations();
        let response_headers = self.build_response_mutations();

        AgentResponse {
            version: PROTOCOL_VERSION_2,
            decision,
            request_headers,
            response_headers,
            routing_metadata: self.routing_metadata,
            audit: AuditMetadata {
                tags: self.tags,
                rule_ids: self.rule_ids,
                confidence: self.confidence,
                reason_codes: self.reason_codes,
                custom: self.custom_metadata,
            },
            needs_more: self.needs_more,
            request_body_mutation: self.request_body_mutation,
            response_body_mutation: self.response_body_mutation,
            websocket_decision: None,
        }
    }

    fn build_request_mutations(&self) -> Vec<HeaderOp> {
        let mut mutations = Vec::new();

        for (name, value) in &self.add_request_headers {
            mutations.push(HeaderOp::Set {
                name: name.clone(),
                value: value.clone(),
            });
        }

        for name in &self.remove_request_headers {
            mutations.push(HeaderOp::Remove { name: name.clone() });
        }

        mutations
    }

    fn build_response_mutations(&self) -> Vec<HeaderOp> {
        let mut mutations = Vec::new();

        for (name, value) in &self.add_response_headers {
            mutations.push(HeaderOp::Set {
                name: name.clone(),
                value: value.clone(),
            });
        }

        for name in &self.remove_response_headers {
            mutations.push(HeaderOp::Remove { name: name.clone() });
        }

        mutations
    }
}

impl From<Decision> for AgentResponse {
    fn from(decision: Decision) -> Self {
        decision.build()
    }
}

/// Shorthand functions for common decisions.
pub mod decisions {
    use super::*;
    use std::collections::HashMap;

    /// Allow the request.
    pub fn allow() -> AgentResponse {
        Decision::allow().build()
    }

    /// Block with 403 Forbidden.
    pub fn deny() -> AgentResponse {
        Decision::deny().build()
    }

    /// Block with 401 Unauthorized.
    pub fn unauthorized() -> AgentResponse {
        Decision::unauthorized().build()
    }

    /// Block with 429 Too Many Requests.
    pub fn rate_limited() -> AgentResponse {
        Decision::rate_limited().build()
    }

    /// Block with custom status and body.
    pub fn block(status_code: u16, body: impl Into<String>) -> AgentResponse {
        Decision::block(status_code).with_body(body).build()
    }

    /// Redirect to URL.
    pub fn redirect(url: impl Into<String>) -> AgentResponse {
        Decision::redirect(url).build()
    }

    /// Challenge with type and parameters.
    pub fn challenge(challenge_type: impl Into<String>, params: HashMap<String, String>) -> AgentResponse {
        Decision::challenge(challenge_type, params).build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow() {
        let response = Decision::allow().build();
        assert!(matches!(response.decision, ProtocolDecision::Allow));
    }

    #[test]
    fn test_block() {
        let response = Decision::block(403)
            .with_body("Access denied")
            .build();

        match &response.decision {
            ProtocolDecision::Block { status, body, .. } => {
                assert_eq!(*status, 403);
                assert_eq!(body.as_deref(), Some("Access denied"));
            }
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_redirect() {
        let response = Decision::redirect("https://example.com/login").build();

        match &response.decision {
            ProtocolDecision::Redirect { url, status } => {
                assert_eq!(url, "https://example.com/login");
                assert_eq!(*status, 302);
            }
            _ => panic!("Expected redirect"),
        }
    }

    #[test]
    fn test_header_mutations() {
        let response = Decision::allow()
            .add_request_header("X-User-ID", "123")
            .remove_request_header("Cookie")
            .add_response_header("X-Processed", "true")
            .build();

        assert_eq!(response.request_headers.len(), 2);
        assert_eq!(response.response_headers.len(), 1);
    }

    #[test]
    fn test_tags_and_metadata() {
        let response = Decision::allow()
            .with_tag("authenticated")
            .with_tags(["verified", "admin"])
            .with_metadata("user_id", serde_json::json!("123"))
            .build();

        assert_eq!(response.audit.tags.len(), 3);
        assert!(response.audit.custom.contains_key("user_id"));
    }

    #[test]
    fn test_convenience_functions() {
        let _allow = decisions::allow();
        let _deny = decisions::deny();
        let _unauth = decisions::unauthorized();
        let _limited = decisions::rate_limited();
        let _block = decisions::block(500, "Error");
        let _redirect = decisions::redirect("/login");
    }

    #[test]
    fn test_json_body() {
        #[derive(serde::Serialize)]
        struct Error { code: u16, message: String }

        let response = Decision::block(400)
            .with_json_body(&Error { code: 400, message: "Bad request".into() })
            .build();

        match &response.decision {
            ProtocolDecision::Block { body, .. } => {
                assert!(body.as_ref().unwrap().contains("Bad request"));
            }
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_rule_ids() {
        let response = Decision::deny()
            .with_rule_id("SQLI-001")
            .with_rule_ids(["XSS-001", "XSS-002"])
            .build();

        assert_eq!(response.audit.rule_ids.len(), 3);
        assert!(response.audit.rule_ids.contains(&"SQLI-001".to_string()));
        assert!(response.audit.rule_ids.contains(&"XSS-001".to_string()));
    }

    #[test]
    fn test_confidence() {
        let response = Decision::deny()
            .with_confidence(0.95)
            .build();

        assert_eq!(response.audit.confidence, Some(0.95_f32));

        // Test clamping
        let response2 = Decision::deny().with_confidence(1.5).build();
        assert_eq!(response2.audit.confidence, Some(1.0_f32));

        let response3 = Decision::deny().with_confidence(-0.5).build();
        assert_eq!(response3.audit.confidence, Some(0.0_f32));
    }

    #[test]
    fn test_reason_codes() {
        let response = Decision::deny()
            .with_reason_code("POLICY_VIOLATION")
            .with_reason_codes(["GEO_BLOCKED", "IP_BLACKLISTED"])
            .build();

        assert_eq!(response.audit.reason_codes.len(), 3);
        assert!(response.audit.reason_codes.contains(&"POLICY_VIOLATION".to_string()));
    }

    #[test]
    fn test_routing_metadata() {
        let response = Decision::allow()
            .with_routing_metadata("upstream", "backend-v2")
            .with_routing_metadata("weight", "100")
            .build();

        assert_eq!(response.routing_metadata.len(), 2);
        assert_eq!(response.routing_metadata.get("upstream"), Some(&"backend-v2".to_string()));
    }

    #[test]
    fn test_needs_more_data() {
        let response = Decision::allow()
            .needs_more_data()
            .build();

        assert!(response.needs_more);

        // Default should be false
        let response2 = Decision::allow().build();
        assert!(!response2.needs_more);
    }

    #[test]
    fn test_body_mutations() {
        let response = Decision::allow()
            .with_request_body_mutation(BodyMutation::replace(0, "modified request body".to_string()))
            .with_response_body_mutation(BodyMutation::replace(0, "modified response body".to_string()))
            .build();

        assert!(response.request_body_mutation.is_some());
        assert!(response.response_body_mutation.is_some());

        let req_mutation = response.request_body_mutation.unwrap();
        assert_eq!(req_mutation.data, Some("modified request body".to_string()));
        assert_eq!(req_mutation.chunk_index, 0);

        let resp_mutation = response.response_body_mutation.unwrap();
        assert_eq!(resp_mutation.data, Some("modified response body".to_string()));
    }

    #[test]
    fn test_combined_audit_fields() {
        let response = Decision::deny()
            .with_rule_id("WAF-001")
            .with_confidence(0.87)
            .with_reason_code("MALICIOUS_PAYLOAD")
            .with_tag("blocked")
            .with_metadata("pattern", serde_json::json!("SELECT.*FROM"))
            .build();

        assert_eq!(response.audit.rule_ids, vec!["WAF-001"]);
        assert_eq!(response.audit.confidence, Some(0.87_f32));
        assert_eq!(response.audit.reason_codes, vec!["MALICIOUS_PAYLOAD"]);
        assert_eq!(response.audit.tags, vec!["blocked"]);
        assert!(response.audit.custom.contains_key("pattern"));
    }

    #[test]
    fn test_body_mutation_drop() {
        let response = Decision::allow()
            .with_request_body_mutation(BodyMutation::drop_chunk(1))
            .build();

        let mutation = response.request_body_mutation.unwrap();
        assert!(mutation.is_drop());
        assert_eq!(mutation.chunk_index, 1);
    }

    #[test]
    fn test_body_mutation_pass_through() {
        let response = Decision::allow()
            .with_response_body_mutation(BodyMutation::pass_through(2))
            .build();

        let mutation = response.response_body_mutation.unwrap();
        assert!(mutation.is_pass_through());
        assert_eq!(mutation.chunk_index, 2);
    }

    #[test]
    fn test_challenge() {
        let mut params = HashMap::new();
        params.insert("site_key".to_string(), "abc123".to_string());

        let response = Decision::challenge("captcha", params).build();

        match &response.decision {
            ProtocolDecision::Challenge { challenge_type, params } => {
                assert_eq!(challenge_type, "captcha");
                assert_eq!(params.get("site_key"), Some(&"abc123".to_string()));
            }
            _ => panic!("Expected challenge decision"),
        }
    }

    #[test]
    fn test_challenge_empty_params() {
        let response = Decision::challenge("js_challenge", HashMap::new()).build();

        match &response.decision {
            ProtocolDecision::Challenge { challenge_type, params } => {
                assert_eq!(challenge_type, "js_challenge");
                assert!(params.is_empty());
            }
            _ => panic!("Expected challenge decision"),
        }
    }

    #[test]
    fn test_challenge_convenience_function() {
        let mut params = HashMap::new();
        params.insert("difficulty".to_string(), "hard".to_string());

        let response = decisions::challenge("proof_of_work", params);

        match &response.decision {
            ProtocolDecision::Challenge { challenge_type, .. } => {
                assert_eq!(challenge_type, "proof_of_work");
            }
            _ => panic!("Expected challenge decision"),
        }
    }
}
