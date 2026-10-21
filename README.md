<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Rust agent SDK</h3>

<p align="center">Write Zentinel agents in Rust, speaking agent protocol v2 over a Unix socket or gRPC.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-rust-sdk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-rust-sdk/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://docs.zentinelproxy.io/agents/v2/">Agent protocol</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The SDK wraps `zentinel-agent-protocol` (the crate the proxy itself uses) in an
`Agent` trait with one async hook per event, a `Decision` builder, and a
runner that serves the agent on a Unix socket or over gRPC. It is published on
crates.io as [`zentinel-agent-sdk`](https://crates.io/crates/zentinel-agent-sdk) 0.3.0.

Maturity: both transports work. The quick start below was run end to end
against Zentinel 0.6.50 on 2026-10-21, over UDS with `AgentRunner` and over
gRPC with `v2::AgentRunnerV2`. CI runs the unit tests, clippy and a build of
the examples.

## Quick start

Create a binary crate and add the SDK (see [Install](#install)), then put
this in `src/main.rs`:

```rust
use zentinel_agent_sdk::prelude::*;

struct HelloAgent;

#[async_trait]
impl Agent for HelloAgent {
    async fn on_request(&self, _request: &Request) -> Decision {
        Decision::allow().add_request_header("X-Hello", "from-agent")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(HelloAgent)
        .with_name("hello")
        .with_socket("/tmp/hello.sock")
        .run()
        .await
}
```

Run it with `cargo run`. It listens on `/tmp/hello.sock`.

Then point Zentinel at the socket. This assumes your config already defines a
listener and an upstream named `backend`:

```kdl
agents {
    agent "hello" type="custom" {
        unix-socket "/tmp/hello.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "hello" {
        type "agent"
        agent "hello"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "hello"
    }
}
```

Check the file with `zentinel test -c zentinel.kdl` and start Zentinel. Every
request on the route then reaches `backend` with `X-Hello: from-agent`.
`failure-mode "closed"` on the filter turns an unreachable agent into a 503
instead of letting requests through unprocessed, so a wiring mistake shows up
on the first request.

For gRPC, serve the agent with `zentinel_agent_sdk::v2::AgentRunnerV2::new(HelloAgent).with_grpc("127.0.0.1:50051".parse()?)`
and replace the `unix-socket` line with `grpc "http://127.0.0.1:50051"`.

## Install

```bash
cargo add zentinel-agent-sdk
cargo add tokio --features full
cargo add anyhow
```

The build compiles the protocol's protobuf definitions, so `protoc` must be on
your `PATH` (`brew install protobuf`, `apt install protobuf-compiler`).
Version 0.3.0 depends on `zentinel-agent-protocol` 0.6.

To track `main` instead of the release:

```toml
zentinel-agent-sdk = { git = "https://github.com/zentinelproxy/zentinel-agent-rust-sdk" }
```

## API overview

- **`Agent`** (async trait): `on_request`, `on_request_body`, `on_response`,
  `on_response_body`, `on_request_complete`, `on_configure`. Every hook has a
  default that allows, so implement only what you need.
- **`ConfigurableAgent`**: typed configuration deserialized with serde from the
  agent's `config` block.
- **`Request` / `Response`**: header (case-insensitive), path, query, client IP,
  correlation ID and body accessors.
- **`Decision`**: `allow()`, `deny()`, `unauthorized()`, `rate_limited()`,
  `block(status)`, `redirect(url)`, `challenge(..)`, then chain
  `add_request_header`, `remove_request_header`, `add_response_header`,
  `with_body`, `with_json_body`, `with_tag`, `with_rule_id`, `with_confidence`,
  `with_metadata`, `with_routing_metadata`, body mutations.
- **`AgentRunner`**: serves an agent on a Unix socket (`with_socket`,
  `with_name`, `with_json_logs`). It does not read command-line flags itself;
  with the default `cli` feature, `zentinel_agent_sdk::cli::parse_args()` gives you
  `--socket` and `--json-logs`. Log level comes from `RUST_LOG`.
- **`v2::AgentRunnerV2`**: `with_uds`, `with_grpc`, or `with_both`.

```rust
Decision::deny()
    .with_body("Access denied")
    .with_tag("blocked")
    .with_rule_id("ADMIN-001")
```

API reference: [docs.rs/zentinel-agent-sdk](https://docs.rs/zentinel-agent-sdk).
Runnable examples are in [`examples/`](examples/) (`cargo run --example simple_agent`).

## Development

```bash
mise install            # Rust stable
cargo build
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

`protoc` is needed for the build, as above. CI runs the same commands on
stable Rust; `Cargo.toml` sets no minimum version.

## Related

- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Guides in this repository](docs/index.md): quickstart, API, configuration, examples
- [API reference on docs.rs](https://docs.rs/zentinel-agent-sdk)
- [Other SDKs](https://github.com/zentinelproxy?q=sdk)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
