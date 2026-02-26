<div align="center">

<h1 align="center">
  Zentinel Agent Rust SDK
</h1>

<p align="center">
  <em>Build agents that extend Zentinel's security and policy capabilities.</em><br>
  <em>Inspect, block, redirect, and transform HTTP traffic.</em>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/">
    <img alt="Rust" src="https://img.shields.io/badge/Rust-1.75+-f74c00?logo=rust&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/zentinelproxy/zentinel">
    <img alt="Zentinel" src="https://img.shields.io/badge/Built%20for-Zentinel-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="docs/index.md">Documentation</a> •
  <a href="docs/quickstart.md">Quickstart</a> •
  <a href="docs/api.md">API Reference</a> •
  <a href="docs/examples.md">Examples</a>
</p>

</div>

---

The Zentinel Agent Rust SDK provides a high-performance, async-first API for building agents that integrate with the [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Agents can inspect requests and responses, block malicious traffic, add headers, and attach audit metadata—all from Rust.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
zentinel-agent-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
```

Create `src/main.rs`:

```rust
use zentinel_agent_sdk::prelude::*;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    async fn on_request(&self, request: &Request) -> Decision {
        if request.path_starts_with("/admin") {
            Decision::deny().with_body("Access denied")
        } else {
            Decision::allow()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_name("my-agent")
        .with_socket("/tmp/my-agent.sock")
        .run()
        .await
}
```

Run the agent:

```bash
cargo run -- --socket /tmp/my-agent.sock
```

## Features

| Feature | Description |
|---------|-------------|
| **Simple Agent API** | Implement `on_request`, `on_response`, and other hooks |
| **Fluent Decision Builder** | Chain methods: `Decision::deny().with_body(...).with_tag(...)` |
| **Request/Response Wrappers** | Ergonomic access to headers, body, query params, metadata |
| **Typed Configuration** | `ConfigurableAgent` trait with serde support |
| **Async Native** | Built on tokio for high-performance concurrent processing |
| **Protocol Compatible** | Full compatibility with Zentinel agent protocol v2 |

## Why Agents?

Zentinel's agent system moves complex logic **out of the proxy core** and into isolated, testable, independently deployable processes:

- **Security isolation** — WAF engines, auth validation, and custom logic run in separate processes
- **Language flexibility** — Write agents in Python, Rust, Go, or any language
- **Independent deployment** — Update agent logic without restarting the proxy
- **Failure boundaries** — Agent crashes don't take down the dataplane

Agents communicate with Zentinel over Unix sockets using a simple length-prefixed JSON protocol.

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client    │────────▶│   Zentinel   │────────▶│   Upstream   │
└─────────────┘         └──────────────┘         └──────────────┘
                               │
                               │ Unix Socket (JSON)
                               ▼
                        ┌──────────────┐
                        │    Agent     │
                        │    (Rust)    │
                        └──────────────┘
```

1. Client sends request to Zentinel
2. Zentinel forwards request headers to agent
3. Agent returns decision (allow, block, redirect) with optional header mutations
4. Zentinel applies the decision
5. Agent can also inspect response headers before they reach the client

---

## Core Concepts

### Agent

The `Agent` trait defines the hooks you can implement:

```rust
use zentinel_agent_sdk::{Agent, Decision, Request, Response};
use async_trait::async_trait;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    /// Agent identifier for logging.
    fn name(&self) -> &str {
        "my-agent"
    }

    /// Called when request headers arrive.
    async fn on_request(&self, request: &Request) -> Decision {
        Decision::allow()
    }

    /// Called when request body is available (if body inspection enabled).
    async fn on_request_body(&self, request: &Request) -> Decision {
        Decision::allow()
    }

    /// Called when response headers arrive from upstream.
    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        Decision::allow()
    }

    /// Called when response body is available (if body inspection enabled).
    async fn on_response_body(&self, request: &Request, response: &Response) -> Decision {
        Decision::allow()
    }

    /// Called when request processing completes. Use for logging/metrics.
    async fn on_request_complete(&self, request: &Request, status: u16, duration_ms: u64) {
    }
}
```

### Request

Access HTTP request data with convenience methods:

```rust
async fn on_request(&self, request: &Request) -> Decision {
    // Path matching
    if request.path_starts_with("/api/") {
        // ...
    }
    if request.path_equals("/health") {
        return Decision::allow();
    }

    // Headers (case-insensitive)
    let auth = request.header("authorization");
    if request.header("x-api-key").is_none() {
        return Decision::unauthorized();
    }

    // Common headers as methods
    let host = request.host();
    let user_agent = request.user_agent();
    let content_type = request.content_type();

    // Query parameters
    let page = request.query("page");

    // Request metadata
    let client_ip = request.client_ip();
    let correlation_id = request.correlation_id();

    // Body (when body inspection is enabled)
    if let Some(body) = request.body() {
        let data = String::from_utf8_lossy(body);
        // Or parse JSON
        if let Ok(payload) = request.body_json::<serde_json::Value>() {
            // ...
        }
    }

    Decision::allow()
}
```

### Response

Inspect upstream responses before they reach the client:

```rust
async fn on_response(&self, request: &Request, response: &Response) -> Decision {
    // Status code
    if response.status_code() >= 500 {
        return Decision::allow().with_tag("upstream-error");
    }

    // Headers
    let content_type = response.header("content-type");

    // Add security headers to all responses
    Decision::allow()
        .add_response_header("X-Frame-Options", "DENY")
        .add_response_header("X-Content-Type-Options", "nosniff")
        .remove_response_header("Server")
}
```

### Decision

Build responses with a fluent API:

```rust
// Allow the request
Decision::allow()

// Block with common status codes
Decision::deny()           // 403 Forbidden
Decision::unauthorized()   // 401 Unauthorized
Decision::rate_limited()   // 429 Too Many Requests
Decision::block(503)       // Custom status

// Block with response body
Decision::deny().with_body("Access denied")
Decision::block(400).with_json_body(&json!({"error": "Invalid request"}))

// Redirect
Decision::redirect("/login")                    // 302 temporary
Decision::redirect_permanent("/new-path")       // 301 permanent

// Modify headers
Decision::allow()
    .add_request_header("X-User-ID", user_id)
    .remove_request_header("Cookie")
    .add_response_header("X-Cache", "HIT")
    .remove_response_header("X-Powered-By")

// Audit metadata (appears in Zentinel logs)
Decision::deny()
    .with_tag("blocked")
    .with_rule_id("SQLI-001")
    .with_confidence(0.95)
    .with_reason_code("MALICIOUS_PAYLOAD")
    .with_metadata("matched_pattern", json!(pattern))

// Routing metadata for upstream selection
Decision::allow()
    .with_routing_metadata("upstream", json!("backend-v2"))

// Request more data before deciding
Decision::allow().needs_more_data()

// Body mutations
Decision::allow()
    .with_request_body_mutation(modified_body)
    .with_response_body_mutation(transformed_body)
```

### ConfigurableAgent

For agents with typed configuration:

```rust
use zentinel_agent_sdk::{ConfigurableAgent, ConfigurableAgentExt, Decision, Request};
use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Default, Deserialize)]
struct RateLimitConfig {
    requests_per_minute: u32,
    enabled: bool,
}

struct RateLimitAgent {
    config: RwLock<RateLimitConfig>,
}

impl RateLimitAgent {
    fn new() -> Self {
        Self {
            config: RwLock::new(RateLimitConfig::default()),
        }
    }
}

impl ConfigurableAgent for RateLimitAgent {
    type Config = RateLimitConfig;

    fn config(&self) -> &RwLock<Self::Config> {
        &self.config
    }

    fn on_config_applied(&self, config: &RateLimitConfig) {
        println!("Rate limit set to {}/min", config.requests_per_minute);
    }
}

#[async_trait]
impl Agent for RateLimitAgent {
    fn name(&self) -> &str {
        "rate-limiter"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let config = self.config.read().await;
        if !config.enabled {
            return Decision::allow();
        }
        // Use config.requests_per_minute...
        Decision::allow()
    }
}
```

---

## Running Agents

### Command Line

The `AgentRunner` parses CLI arguments:

```bash
# Basic usage
cargo run -- --socket /tmp/my-agent.sock

# With options
cargo run -- \
    --socket /tmp/my-agent.sock \
    --log-level debug \
    --json-logs
```

| Option | Description | Default |
|--------|-------------|---------|
| `--socket PATH` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `--log-level LEVEL` | trace, debug, info, warn, error | `info` |
| `--json-logs` | Output logs as JSON | disabled |

### Programmatic

```rust
use zentinel_agent_sdk::AgentRunner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_name("my-agent")
        .with_socket("/tmp/my-agent.sock")
        .with_log_level("debug")
        .with_json_logs()
        .run()
        .await
}
```

---

## Zentinel Configuration

Configure Zentinel to connect to your agent:

```kdl
agents {
    agent "my-agent" type="custom" {
        unix-socket path="/tmp/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "open"
    }
}

filters {
    filter "my-filter" {
        type "agent"
        agent "my-agent"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "my-filter"
    }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `unix-socket path="..."` | Path to agent's Unix socket | required |
| `events` | Events to send: `request_headers`, `request_body`, `response_headers`, `response_body` | `request_headers` |
| `timeout-ms` | Timeout for agent calls | `1000` |
| `failure-mode` | `"open"` (allow on failure) or `"closed"` (block on failure) | `"open"` |

See [docs/configuration.md](docs/configuration.md) for complete configuration reference.

---

## Examples

The `examples/` directory contains complete, runnable examples:

| Example | Description |
|---------|-------------|
| [`simple_agent`](examples/simple_agent.rs) | Basic request blocking and header modification |
| [`configurable_agent`](examples/configurable_agent.rs) | Rate limiting with typed configuration |
| [`body_inspection_agent`](examples/body_inspection_agent.rs) | Request and response body inspection |

Run an example:

```bash
cargo run --example simple_agent -- --socket /tmp/simple-agent.sock
```

See [docs/examples.md](docs/examples.md) for more patterns: authentication, rate limiting, IP filtering, header transformation, and more.

---

## Development

This project uses [mise](https://mise.jdx.dev/) for tool management.

```bash
# Install tools
mise install

# Build
cargo build

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy

# Build documentation
cargo doc --open
```

### Without mise

```bash
# Requires Rust 1.75+
cargo build
cargo test
```

### Project Structure

```
zentinel-agent-rust-sdk/
├── src/
│   ├── lib.rs            # Public API exports and prelude
│   ├── agent.rs          # Agent trait and AgentHandler
│   ├── decision.rs       # Decision builder
│   ├── request.rs        # Request wrapper
│   ├── response.rs       # Response wrapper
│   └── runner.rs         # AgentRunner and CLI handling
├── examples/             # Example agents
├── Cargo.toml
└── mise.toml
```

---

## Protocol

This SDK implements Zentinel Agent Protocol v2:

- **Transport**: Unix domain sockets (UDS) or gRPC
- **Encoding**: Length-prefixed JSON (4-byte big-endian length prefix) for UDS
- **Max message size**: 10 MB
- **Events**: `configure`, `request_headers`, `request_body_chunk`, `response_headers`, `response_body_chunk`, `request_complete`, `websocket_frame`, `guardrail_inspect`
- **Decisions**: `allow`, `block`, `redirect`, `challenge`

The protocol is designed for low latency and high throughput, with support for streaming body inspection.

For the canonical protocol specification, see the [Zentinel Agent Protocol documentation](https://github.com/zentinelproxy/zentinel/tree/main/crates/agent-protocol).

---

## Community

- [Issues](https://github.com/zentinelproxy/zentinel-agent-rust-sdk/issues) — Bug reports and feature requests
- [Zentinel Discussions](https://github.com/zentinelproxy/zentinel/discussions) — Questions and ideas
- [Zentinel Documentation](https://zentinelproxy.io/docs) — Proxy documentation

Contributions welcome. Please open an issue to discuss significant changes before submitting a PR.

---

## License

Apache 2.0 — See [LICENSE](LICENSE).
