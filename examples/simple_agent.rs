//! A simple agent that demonstrates the SDK usage.
//!
//! This agent blocks requests to `/blocked` and adds headers to all other requests.

use zentinel_agent_sdk::prelude::*;

struct SimpleAgent;

#[async_trait]
impl Agent for SimpleAgent {
    fn name(&self) -> &str {
        "simple-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Log the request
        tracing::info!(
            method = request.method(),
            path = request.path(),
            client_ip = request.client_ip(),
            "Processing request"
        );

        // Block requests to /blocked
        if request.path_starts_with("/blocked") {
            return Decision::deny()
                .with_body("This path is blocked")
                .with_tag("blocked-path");
        }

        // Require auth for /api paths
        if request.path_starts_with("/api") && request.header("authorization").is_none() {
            return Decision::unauthorized().with_body("Authorization required");
        }

        // Allow other requests, adding some headers
        Decision::allow()
            .add_request_header("X-Processed-By", "simple-agent")
            .add_request_header("X-Client-IP", request.client_ip())
    }

    async fn on_response(&self, _request: &Request, response: &Response) -> Decision {
        // Add security headers to HTML responses
        if response.is_html() {
            Decision::allow()
                .add_response_header("X-Content-Type-Options", "nosniff")
                .add_response_header("X-Frame-Options", "DENY")
        } else {
            Decision::allow()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(SimpleAgent)
        .with_name("simple-agent")
        .with_socket("/tmp/simple-agent.sock")
        .run()
        .await
}
